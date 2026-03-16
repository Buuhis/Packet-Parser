#define _GNU_SOURCE
#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"
#include "proto/mwan_proto.h"
#include "proto/fragment.h"
#include "config/db_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <features.h>

/* ---------- global state ---------- */

static volatile int running_server = 1;
static volatile int running_dataplane = 0;

static int unix_server_fd = -1;
static char socket_path[256] = "/var/run/sep-wan.sock";

static afpkt_fanout_t fg_out;
static afpkt_worker_t in_workers[MAX_NE_TUNNELS];
static size_t in_worker_count = 0;
static int total_worker_threads = 0;

static pthread_t gc_thread;
static pthread_t *worker_threads = NULL;

static app_context_t running_ctx;
static int is_dataplane_active = 0;

/* ---------- thread affinity ---------- */

static int bind_thread_to_core(pthread_t thread, int core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    return pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}

static inline int get_next_odd_core(int *current_idx, int max_cores) {
    if (max_cores <= 1) return 0;
    
    int core = *current_idx;
    if (core % 2 == 0) core++; 
    
    if (core >= max_cores) {
        core = 1;
    }
    
    *current_idx = core + 2;
    return core;
}

/* ---------- signal handler ---------- */

static void handle_signal(int sig)
{
    (void)sig;
    running_server = 0;
    running_dataplane = 0;
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unix_server_fd = -1;
        unlink(socket_path);
    }
}

/* ---------- usage ---------- */

static void usage(const char *prog)
{
    printf("=========================================================\n");
    printf("         MULTI-WAN PACKET FORWARDER (sep-wan)            \n");
    printf("=========================================================\n");
    printf("Client Mode (Control running daemon):\n");
    printf("  %s -id <node_id>    Send config request to the daemon\n", prog);
    printf("  %s --help | -h      Show this help message and exit\n", prog);
    printf("\n");
    printf("Daemon Mode (Start the background service):\n");
    printf("  Run without arguments to start the daemon.\n");
    printf("  Requires ENV vars: DB_HOST, DB_PORT, DB_USER, DB_NAME, [DB_PASS]\n");
    printf("=========================================================\n");
}

/* ---- Outbound worker thread args ---- */
typedef struct {
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
} out_arg_t;

static void *out_fn(void *a) {
    out_arg_t *o = (out_arg_t *)a;
    afpkt_worker_loop_outbound(o->worker, o->fg, o->ctx, o->running);
    return NULL;
}

/* ---- Inbound workers (1 per ne_tunnel, unchanged) ---- */
typedef struct {
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    char           listen_ifname[IF_NAMESIZE]; // Changed from 16 to IF_NAMESIZE
    volatile int *running;
} in_arg_t;

static void *in_fn(void *a) {
    in_arg_t *ina = (in_arg_t *)a;
    afpkt_worker_loop_inbound(ina->worker, ina->fg, ina->ctx, ina->listen_ifname, ina->running);
    return NULL;
}

static void *gc_worker_fn(void *arg)
{
    struct frag_table *ft = (struct frag_table *)arg;
    while (running_dataplane) {
        frag_table_gc(ft);
        usleep(100000); /* 100ms */
    }
    return NULL;
}

/* ---------- Dataplane Start / Stop ---------- */

static out_arg_t g_out_args[MAX_FANOUT_WORKERS];
static in_arg_t g_in_args[MAX_NE_TUNNELS];

static void stop_dataplane(void) {
    if (!is_dataplane_active) return;
    
    log_info("Stopping Dataplane...");
    running_dataplane = 0;
    
    if (worker_threads) {
        for (int i = 0; i < total_worker_threads; i++) {
            pthread_join(worker_threads[i], NULL);
        }
        free(worker_threads);
        worker_threads = NULL;
    }
    pthread_join(gc_thread, NULL);
    
    if (fg_out.frag_tbl) {
        free(fg_out.frag_tbl);
        fg_out.frag_tbl = NULL;
    }
    
    afpkt_fanout_close(&fg_out);

    /* Close individual inbound workers */
    for (size_t i = 0; i < in_worker_count; i++) {
        if (in_workers[i].ring) {
            munmap(in_workers[i].ring, in_workers[i].ring_size);
            in_workers[i].ring = NULL;
        }
        if (in_workers[i].rx_fd >= 0) close(in_workers[i].rx_fd);
        if (in_workers[i].tx_fd >= 0) close(in_workers[i].tx_fd);
    }
    in_worker_count = 0;
    
    system_restore_ip_forward();
    netdev_enable_offloads(running_ctx.cfg.local_if);
    netdev_reset_interface(running_ctx.cfg.local_if);
    
    is_dataplane_active = 0;
    total_worker_threads = 0;
    log_info("Dataplane stopped cleanly.");
}

static int start_dataplane(app_context_t *ctx) {
    if (is_dataplane_active) {
        stop_dataplane();
    }
    
    log_info("Starting Dataplane for node: %s", ctx->cfg.node_id);
    running_dataplane = 1;
    
    /* ---- STEP 1: disable ip_forward ---- */
    if (system_disable_ip_forward() != 0) {
        log_error("Failed to disable IP forwarding");
        return -1;
    }

    /* ---- STEP 2: Disable offloads + Optimize Interfaces ---- */
    netdev_disable_offloads(ctx->cfg.local_if);
    netdev_optimize_interface(ctx->cfg.local_if);

    /* ---- STEP 3: Open fanout on local_if (Capture LAN) ---- */
    if (afpkt_fanout_open(&fg_out, ctx->cfg.local_if, 1, NUM_TX_WORKERS) != 0) {
        log_error("Failed to open fanout outbound on %s", ctx->cfg.local_if);
        goto cleanup_route;
    }

    /* ---- STEP 4: Fragment Table (Shared across all workers) ---- */
    struct frag_table *ft = malloc(sizeof(struct frag_table));
    if (ft) {
        frag_table_init(ft);
        fg_out.frag_tbl = ft;
    } else {
        log_error("Failed to allocate fragment table!");
        goto cleanup_pl_out;
    }

    /* ---- STEP 5: Open 1 Inbound Worker per Tunnel (Bind to specific interface) ---- */
    in_worker_count = 0;
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count && i < MAX_NE_TUNNELS; i++) {
        const char *tnl_if = ctx->cfg.ne_tunnels[i].ifname;
        if (afpkt_single_open_inbound(&in_workers[in_worker_count], tnl_if, (int)i) == 0) {
            in_worker_count++;
        } else {
            log_error("Failed to open inbound worker for tunnel %s", tnl_if);
        }
    }

    /* ---- STEP 6: Init caches ---- */
    afpkt_fanout_init_cache_outbound(&fg_out, ctx);
    afpkt_fanout_init_cache_inbound(&fg_out, ctx); /* Populate LAN info (MAC/ifindex) */

    int num_available_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_available_cores <= 0) num_available_cores = 1;
    int current_core_idx = 1;

    if (pthread_create(&gc_thread, NULL, gc_worker_fn, fg_out.frag_tbl) != 0) {
        log_error("Failed to create GC thread");
        goto cleanup_pl_out;
    }
    int gc_core = get_next_odd_core(&current_core_idx, num_available_cores);
    bind_thread_to_core(gc_thread, gc_core);

    /* Total Workers: fg_out workers + N inbound workers */
    int max_threads = fg_out.num_workers + (int)in_worker_count;
    worker_threads = calloc(max_threads, sizeof(pthread_t));
    total_worker_threads = 0;

    /* Start Outbound workers */
    for (int i = 0; i < fg_out.num_workers; i++) {
        g_out_args[i] = (out_arg_t){
            .worker = &fg_out.workers[i],
            .fg = &fg_out,
            .ctx = ctx,
            .running = &running_dataplane,
        };
        pthread_create(&worker_threads[total_worker_threads], NULL, out_fn, &g_out_args[i]);
        int core_id = get_next_odd_core(&current_core_idx, num_available_cores);
        bind_thread_to_core(worker_threads[total_worker_threads], core_id);
        total_worker_threads++;
    }

    /* Start Inbound workers */
    for (size_t i = 0; i < in_worker_count; i++) {
        g_in_args[i] = (in_arg_t){
            .worker = &in_workers[i],
            .fg = &fg_out, /* Share local cache and frag_tbl */
            .ctx = ctx,
            .running = &running_dataplane,
        };
        pthread_create(&worker_threads[total_worker_threads], NULL, in_fn, &g_in_args[i]);
        int core_id = get_next_odd_core(&current_core_idx, num_available_cores);
        bind_thread_to_core(worker_threads[total_worker_threads], core_id);
        total_worker_threads++;
    }

    log_info("===========================================");
    log_info("  MWAN Turbo Per-Tunnel Pipeline Started");
    log_info("  Outbound workers: %d, Inbound workers: %zu", fg_out.num_workers, in_worker_count);
    log_info("===========================================");
    is_dataplane_active = 1;
    return 0;

cleanup_threads:
    running_dataplane = 0;
    for (int k = 0; k < total_worker_threads; k++) pthread_join(worker_threads[k], NULL);
    pthread_join(gc_thread, NULL);
    free(worker_threads); worker_threads = NULL;

cleanup_pl_out:
    if (fg_out.frag_tbl) { free(fg_out.frag_tbl); fg_out.frag_tbl = NULL; }
    afpkt_fanout_close(&fg_out);
    for (size_t i = 0; i < in_worker_count; i++) {
        if (in_workers[i].ring) munmap(in_workers[i].ring, in_workers[i].ring_size);
        if (in_workers[i].rx_fd >= 0) close(in_workers[i].rx_fd);
        if (in_workers[i].tx_fd >= 0) close(in_workers[i].tx_fd);
    }
    in_worker_count = 0;
cleanup_route:
    system_restore_ip_forward();
    netdev_enable_offloads(ctx->cfg.local_if);
    netdev_reset_interface(ctx->cfg.local_if);
    is_dataplane_active = 0;
    return -1;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *env_sock = getenv("MWAN_SOCKET_PATH");
    if (env_sock) {
        strncpy(socket_path, env_sock, sizeof(socket_path)-1);
    } else {
        strncpy(socket_path, "/var/run/sep-wan.sock", sizeof(socket_path)-1);
    }

    log_set_level(LOG_INFO);

    int client_mode = 0;
    const char *node_id = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            client_mode = 1;
            node_id = argv[++i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (client_mode) {
        if (!node_id) {
            fprintf(stderr, "Error: Missing -id argument.\n");
            usage(argv[0]);
            return 1;
        }

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("Error creating socket");
            return 1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        size_t slen = strlen(socket_path);
        if (slen >= sizeof(addr.sun_path)) slen = sizeof(addr.sun_path) - 1;
        memcpy(addr.sun_path, socket_path, slen);
        addr.sun_path[slen] = '\0';

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "[-] Connection refused!\n");
            fprintf(stderr, "    Make sure the daemon is currently running.\n");
            fprintf(stderr, "    (Target socket: %s)\n", socket_path);
            close(fd);
            return 1;
        }

        if (send(fd, node_id, strlen(node_id), 0) < 0) {
            perror("[-] Failed to send command to daemon");
            close(fd);
            return 1;
        }

        printf("[+] Command sent successfully! Node ID: '%s'\n", node_id);
        close(fd);
        return 0;
    }

    /* DAEMON MODE */
    const char *db_host = getenv("DB_HOST");
    const char *db_port = getenv("DB_PORT");
    const char *db_user = getenv("DB_USER");
    const char *db_name = getenv("DB_NAME");
    const char *db_pass = getenv("DB_PASS");

    if (!db_host || !db_port || !db_user || !db_name) {
        log_error("Missing ENV: DB_HOST, DB_PORT, DB_USER, or DB_NAME");
        usage(argv[0]);
        return 1;
    }

    if (db_client_connect(db_host, db_port, db_user, db_name, db_pass) == 0) {
        log_info("Successfully connected to Database.");
    } else {
        log_error("Failed to connect to DB! Please check DB credentials and DB_PASS env. Exiting.");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    /* Create Unix Domain Socket */
    unix_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_server_fd < 0) {
        log_error("socket(AF_UNIX) failed: %s", strerror(errno));
        db_client_disconnect();
        return 1;
    }
    
    /* Remove old socket file if it exists */
    unlink(socket_path);

    struct sockaddr_un saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    size_t slen = strlen(socket_path);
    if (slen >= sizeof(saddr.sun_path)) slen = sizeof(saddr.sun_path) - 1;
    memcpy(saddr.sun_path, socket_path, slen);
    saddr.sun_path[slen] = '\0';
    
    if (bind(unix_server_fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        log_error("bind on socket %s failed: %s", socket_path, strerror(errno));
        db_client_disconnect();
        return 1;
    }
    
    if (listen(unix_server_fd, 5) < 0) {
        log_error("listen failed: %s", strerror(errno));
        db_client_disconnect();
        return 1;
    }
    
    log_info("==================================================");
    log_info("Control Plane Ready!");
    log_info("Waiting for node_id on UNIX Socket: %s", socket_path);
    log_info("==================================================");

    while(running_server) {
        int client_fd = accept(unix_server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (running_server) log_error("accept failed: %s", strerror(errno));
            continue;
        }
        
        char buf[128] = {0};
        int n = recv(client_fd, buf, sizeof(buf)-1, 0);
        close(client_fd);
        if (n <= 0) continue;
        
        while(n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n')) buf[--n] = '\0';
        
        log_info(">>> Received configure request for node_id: '%s'", buf);
        
        app_config_t new_cfg;
        if (db_client_load_config(buf, &new_cfg) == 0) {
            app_context_dump(&(app_context_t){new_cfg});
            
            log_info("Applying new config...");
            memset(&running_ctx, 0, sizeof(running_ctx));
            running_ctx.cfg = new_cfg;
            
            if (start_dataplane(&running_ctx) != 0) {
                log_error("Failed to start dataplane for node: %s", buf);
            }
        } else {
            log_error("Config load failed. Skipping this node_id.");
        }
    }
    
    log_info("Server shutting down...");
    stop_dataplane();
    db_client_disconnect();
    
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unlink(socket_path);
    }
    return 0;
}
