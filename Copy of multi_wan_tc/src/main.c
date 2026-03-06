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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <features.h>

/* ---------- global state ---------- */

static volatile int running_server = 1;
static volatile int running_dataplane = 0;

static int tcp_server_fd = -1;

static afpkt_pipeline_t pipeline;
static afpkt_fanout_t fg_out;
static afpkt_worker_t in_workers[MAX_NE_TUNNELS];
static size_t in_worker_count = 0;

static pthread_t gc_thread;
static pthread_t *worker_threads = NULL;
static int total_worker_threads = 0;

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

/* ---------- signal handler ---------- */

static void handle_signal(int sig)
{
    (void)sig;
    running_server = 0;
    running_dataplane = 0;
    if (tcp_server_fd >= 0) {
        close(tcp_server_fd);
        tcp_server_fd = -1;
    }
}

/* ---------- usage ---------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --db-host <host> --db-port <port> --db-user <user> --db-name <name> --listen-port <port>\n", prog);
}

/* ---- Pipeline RX thread arg ---- */
typedef struct {
    afpkt_worker_t *rx;
    const afpkt_fanout_t *fg;
    struct pkt_queue **queues;
    int num_queues;
    volatile int *running;
} rx_arg_t;

static void *rx_fn(void *a) {
    rx_arg_t *r = (rx_arg_t *)a;
    afpkt_rx_distribute_loop(r->rx, r->fg, r->queues, r->num_queues, r->running);
    return NULL;
}

/* ---- Pipeline TX worker thread args ---- */
typedef struct {
    int id;
    struct pkt_queue *q;
    int tx_fd;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
} tx_arg_t;

static void *tx_fn(void *a) {
    tx_arg_t *t = (tx_arg_t *)a;
    afpkt_tx_worker_loop(t->id, t->q, t->tx_fd, t->fg, t->ctx, t->running);
    return NULL;
}

/* ---- Inbound workers (1 per ne_tunnel, unchanged) ---- */
typedef struct {
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
} in_arg_t;

static void *in_fn(void *a) {
    in_arg_t *ina = (in_arg_t *)a;
    afpkt_worker_loop_inbound(ina->worker, ina->fg, ina->ctx, ina->running);
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

/* ---------- helper: close single worker ---------- */

static void worker_close(afpkt_worker_t *w)
{
    if (w->ring)
    {
        munmap(w->ring, w->ring_size);
        w->ring = NULL;
    }
    if (w->tx_fd >= 0)
    {
        close(w->tx_fd);
        w->tx_fd = -1;
    }
    if (w->rx_fd >= 0)
    {
        close(w->rx_fd);
        w->rx_fd = -1;
    }
}

/* ========================================================================= */
/* DATAPLANE START / STOP */
/* ========================================================================= */

static rx_arg_t g_rx_arg;
static tx_arg_t g_tx_args[MAX_TX_WORKERS];
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
    
    for (size_t w = 0; w < in_worker_count; w++) {
        worker_close(&in_workers[w]);
    }
    
    if (fg_out.frag_tbl) {
        free(fg_out.frag_tbl);
        fg_out.frag_tbl = NULL;
    }
    
    afpkt_pipeline_close(&pipeline);
    
    system_restore_ip_forward();
    netdev_enable_offloads(running_ctx.cfg.local_if);
    netdev_reset_interface(running_ctx.cfg.local_if);
    
    is_dataplane_active = 0;
    in_worker_count = 0;
    total_worker_threads = 0;
    log_info("Dataplane stopped cleanly.");
}

static int start_dataplane(app_context_t *ctx) {
    if (is_dataplane_active) {
        stop_dataplane();
    }
    
    log_info("Starting Dataplane for node: %s", ctx->cfg.node_id);
    running_dataplane = 1;
    
    /* ---- STEP 1: enable ip_forward ---- */
    if (system_disable_ip_forward() != 0) {
        log_error("Failed to enable IP forwarding");
        return -1;
    }

    /* ---- STEP 2: Disable offloads + Optimize Interfaces ---- */
    netdev_disable_offloads(ctx->cfg.local_if);
    netdev_optimize_interface(ctx->cfg.local_if);

    if (afpkt_pipeline_open(&pipeline, ctx->cfg.local_if, NUM_TX_WORKERS) != 0) {
        log_error("Failed to open pipeline on %s", ctx->cfg.local_if);
        goto cleanup_route;
    }

    memset(&fg_out, 0, sizeof(fg_out));
    struct frag_table *ft = malloc(sizeof(struct frag_table));
    if (ft) {
        frag_table_init(ft);
        fg_out.frag_tbl = ft;
    } else {
        log_error("Failed to allocate fragment table!");
        goto cleanup_pl;
    }

    in_worker_count = 0;
    for (size_t w = 0; w < ctx->cfg.ne_tunnel_count; w++) {
        in_workers[w].id = (int)w;
        if (afpkt_single_open(&in_workers[w], ctx->cfg.ne_tunnels[w].ifname) != 0) {
            log_error("Failed to open inbound on %s", ctx->cfg.ne_tunnels[w].ifname);
            goto cleanup_inbound;
        }
        in_worker_count++;
    }

    afpkt_fanout_init_cache_outbound(&fg_out, ctx);
    afpkt_fanout_init_cache_inbound(&fg_out, ctx);

    int num_available_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_available_cores <= 0) num_available_cores = 1; /* Fallback */
    int current_core_idx = 1; /* Start from 1 to leave CPU 0 for OS */

    if (pthread_create(&gc_thread, NULL, gc_worker_fn, fg_out.frag_tbl) != 0) {
        log_error("Failed to create GC thread");
        goto cleanup_inbound;
    }
    int gc_core = current_core_idx % num_available_cores;
    if (bind_thread_to_core(gc_thread, gc_core) == 0)
        log_info("Bound GC thread to core %d", gc_core);
    current_core_idx++;

    int max_threads = 1 + pipeline.num_tx_workers + (int)ctx->cfg.ne_tunnel_count;
    worker_threads = calloc(max_threads, sizeof(pthread_t));
    total_worker_threads = 0;

    g_rx_arg = (rx_arg_t){
        .rx = &pipeline.rx,
        .fg = &fg_out,
        .queues = pipeline.queues,
        .num_queues = pipeline.num_tx_workers,
        .running = &running_dataplane,
    };
    if (pthread_create(&worker_threads[total_worker_threads], NULL, rx_fn, &g_rx_arg) != 0) {
        log_error("Failed to create RX thread");
        goto cleanup_threads;
    }
    int rx_core = current_core_idx % num_available_cores;
    if (bind_thread_to_core(worker_threads[total_worker_threads], rx_core) == 0)
        log_info("Bound pipeline RX to core %d", rx_core);
    current_core_idx++;
    total_worker_threads++;

    for (int i = 0; i < pipeline.num_tx_workers; i++) {
        g_tx_args[i] = (tx_arg_t){
            .id = i,
            .q = pipeline.queues[i],
            .tx_fd = pipeline.tx_fds[i],
            .fg = &fg_out,
            .ctx = ctx,
            .running = &running_dataplane,
        };
        if (pthread_create(&worker_threads[total_worker_threads], NULL, tx_fn, &g_tx_args[i]) != 0) {
            log_error("Failed to create TX worker %d", i);
            goto cleanup_threads;
        }
        int core_id = current_core_idx % num_available_cores;
        if (bind_thread_to_core(worker_threads[total_worker_threads], core_id) == 0)
            log_info("Bound pipeline TX worker %d to core %d", i, core_id);
        current_core_idx++;
        total_worker_threads++;
    }

    for (size_t w = 0; w < ctx->cfg.ne_tunnel_count; w++) {
        g_in_args[w] = (in_arg_t){
            .worker = &in_workers[w],
            .fg = &fg_out,
            .ctx = ctx,
            .running = &running_dataplane,
        };
        if (pthread_create(&worker_threads[total_worker_threads], NULL, in_fn, &g_in_args[w]) != 0) {
            log_error("Failed to create inbound worker tunnel[%zu]", w);
            goto cleanup_threads;
        }
        int core_id = current_core_idx % num_available_cores;
        if (bind_thread_to_core(worker_threads[total_worker_threads], core_id) == 0)
            log_info("Bound inbound worker %zu to core %d", w, core_id);
        current_core_idx++;
        total_worker_threads++;
    }

    log_info("===========================================");
    log_info("  MWAN Pipeline Forwarding Started");
    log_info("  Threads: 1 RX + %d TX + %d inbound + 1 GC",
             pipeline.num_tx_workers, (int)ctx->cfg.ne_tunnel_count);
    log_info("===========================================");
    is_dataplane_active = 1;
    return 0;

cleanup_threads:
    running_dataplane = 0;
    for (int k = 0; k < total_worker_threads; k++) {
        pthread_join(worker_threads[k], NULL);
    }
    pthread_join(gc_thread, NULL);
    free(worker_threads);
    worker_threads = NULL;

cleanup_inbound:
    for (size_t w = 0; w < in_worker_count; w++) worker_close(&in_workers[w]);
    if (fg_out.frag_tbl) { free(fg_out.frag_tbl); fg_out.frag_tbl = NULL; }
cleanup_pl:
    afpkt_pipeline_close(&pipeline);
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
    const char *db_host = NULL;
    const char *db_port = NULL;
    const char *db_user = NULL;
    const char *db_name = NULL;
    int listen_port = 0;

    log_set_level(LOG_INFO);

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--db-host") == 0 && i + 1 < argc) {
            db_host = argv[++i];
        } else if (strcmp(argv[i], "--db-port") == 0 && i + 1 < argc) {
            db_port = argv[++i];
        } else if (strcmp(argv[i], "--db-user") == 0 && i + 1 < argc) {
            db_user = argv[++i];
        } else if (strcmp(argv[i], "--db-name") == 0 && i + 1 < argc) {
            db_name = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!db_host || !db_port || !db_user || !db_name || listen_port <= 0) {
        log_error("Missing required arguments.");
        usage(argv[0]);
        return 1;
    }

    char password[256] = {0};
    int attempts = 0;
    while(attempts < 3) {
        char *p = getpass("Enter DB password: ");
        if (p) {
            strncpy(password, p, sizeof(password)-1);
            if (db_client_connect(db_host, db_port, db_user, db_name, password) == 0) {
                log_info("Successfully connected to Database.");
                break;
            }
        }
        attempts++;
        if (attempts < 3) {
            printf("Connection failed. Attempt %d of 3. Please try again.\n", attempts + 1);
        }
    }
    
    if (attempts >= 3) {
        log_error("Failed to connect to DB after 3 attempts. Exiting.");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(listen_port);
    
    if (bind(tcp_server_fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        log_error("bind on port %d failed: %s", listen_port, strerror(errno));
        db_client_disconnect();
        return 1;
    }
    
    if (listen(tcp_server_fd, 5) < 0) {
        log_error("listen failed: %s", strerror(errno));
        db_client_disconnect();
        return 1;
    }
    
    log_info("==================================================");
    log_info("Control Plane Ready!");
    log_info("Waiting for node_id on TCP Port %d...", listen_port);
    log_info("==================================================");

    while(running_server) {
        int client_fd = accept(tcp_server_fd, NULL, NULL);
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
    
    return 0;
}
