#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"
#include "proto/mwan_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <features.h>

/* ---------- global state ---------- */

static volatile int running = 1;

/* ---------- signal handler ---------- */

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ---------- usage ---------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --config <file> --node <id> [--dump-config]\n", prog);
}

/* ---------- worker thread arg ---------- */

typedef struct
{
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
    int is_outbound;
} worker_thread_arg_t;

static void *worker_fn(void *arg)
{
    worker_thread_arg_t *a = (worker_thread_arg_t *)arg;
    if (a->is_outbound)
        afpkt_worker_loop_outbound(a->worker, a->fg, a->ctx, a->running);
    else
        afpkt_worker_loop_inbound(a->worker, a->fg, a->ctx, a->running);
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

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *node_id = NULL;
    int dump = 0;

    log_set_level(LOG_INFO);

    /* ---- parse args ---- */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                usage(argv[0]);
                return 2;
            }
            config_path = argv[++i];
        }
        else if (strcmp(argv[i], "--node") == 0)
        {
            if (i + 1 >= argc)
            {
                usage(argv[0]);
                return 2;
            }
            node_id = argv[++i];
        }
        else if (strcmp(argv[i], "--dump-config") == 0)
        {
            dump = 1;
        }
        else if (strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            log_error("Unknown argument: %s", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!config_path || !node_id)
    {
        usage(argv[0]);
        return 2;
    }

    /* ---- load config ---- */
    app_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (app_context_init(&ctx, config_path, node_id) != 0)
    {
        log_error("Failed to load config");
        return 1;
    }

    if (dump)
        app_context_dump(&ctx);

    if (ctx.cfg.ne_tunnel_count == 0)
    {
        log_error("No ne_tunnel defined for node %s", node_id);
        return 1;
    }

    /* ---- STEP 1: enable ip_forward ---- */
    if (system_disable_ip_forward() != 0)
    {
        log_error("Failed to enable IP forwarding");
        return 1;
    }

    /* ---- STEP 2: force routing into TC ---- */
    if (system_add_route_dev(ctx.cfg.remote_cidr, ctx.cfg.local_if) != 0)
    {
        log_error("Failed to add route for %s via %s",
                  ctx.cfg.remote_cidr, ctx.cfg.local_if);
        return 1;
    }

    /* ---- STEP 3: Optimize Interfaces ---- */
    netdev_optimize_interface(ctx.cfg.local_if);
    for (size_t i = 0; i < ctx.cfg.wan_count; i++)
        netdev_optimize_interface(ctx.cfg.wans[i].ifname);

    /* ===================================================== */
    /* ==== FANOUT: outbound workers on local_if =========== */
    /* ===================================================== */

    afpkt_fanout_t fg_out;
    if (afpkt_fanout_open(&fg_out, ctx.cfg.local_if, 1) != 0)
    {
        log_error("Failed to open fanout outbound on %s", ctx.cfg.local_if);
        goto cleanup_route;
    }

    /* ===================================================== */
    /* ==== INBOUND: 1 single socket per ne_tunnel ========= */
    /* ===================================================== */

    afpkt_worker_t in_workers[MAX_NE_TUNNELS];
    size_t in_worker_count = 0;
    memset(in_workers, 0, sizeof(in_workers));
    for (size_t i = 0; i < MAX_NE_TUNNELS; i++)
    {
        in_workers[i].rx_fd = -1;
        in_workers[i].tx_fd = -1;
    }

    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++)
    {
        in_workers[w].id = (int)w;
        if (afpkt_single_open(&in_workers[w], ctx.cfg.ne_tunnels[w].ifname) != 0)
        {
            log_error("Failed to open inbound on %s", ctx.cfg.ne_tunnels[w].ifname);
            goto cleanup_inbound;
        }
        in_worker_count++;
    }

    /* ===================================================== */
    /* ==== TC DROP (Optional) ============================= */
    /* ===================================================== */

    // tc_ingress_drop_cidr(ctx.cfg.local_if, ctx.cfg.remote_cidr);

    /* ===================================================== */
    /* ==== INIT CACHES ==================================== */
    /* ===================================================== */

    afpkt_fanout_init_cache_outbound(&fg_out, &ctx);
    afpkt_fanout_init_cache_inbound(&fg_out, &ctx);

    /* ===================================================== */
    /* ==== START THREADS ================================== */
    /* ===================================================== */

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int total_out = NUM_WORKERS;
    int total_in = (int)ctx.cfg.ne_tunnel_count;
    int total_threads = total_out + total_in;

    pthread_t threads[NUM_WORKERS + MAX_NE_TUNNELS];
    worker_thread_arg_t args[NUM_WORKERS + MAX_NE_TUNNELS];
    int tidx = 0;

    /* Outbound workers (fanout on local_if) */
    for (int i = 0; i < NUM_WORKERS; i++)
    {
        args[tidx] = (worker_thread_arg_t){
            .worker = &fg_out.workers[i],
            .fg = &fg_out,
            .ctx = &ctx,
            .running = &running,
            .is_outbound = 1,
        };
        if (pthread_create(&threads[tidx], NULL, worker_fn, &args[tidx]) != 0)
        {
            log_error("Failed to create outbound worker %d", i);
            running = 0;
            for (int k = 0; k < tidx; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_inbound;
        }
        tidx++;
    }

    /* Inbound workers (1 per ne_tunnel) */
    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++)
    {
        args[tidx] = (worker_thread_arg_t){
            .worker = &in_workers[w],
            .fg = &fg_out, /* Needed for local interface cache */
            .ctx = &ctx,
            .running = &running,
            .is_outbound = 0,
        };
        if (pthread_create(&threads[tidx], NULL, worker_fn, &args[tidx]) != 0)
        {
            log_error("Failed to create inbound worker tunnel[%zu]", w);
            running = 0;
            for (int k = 0; k < tidx; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_inbound;
        }
        tidx++;
    }

    log_info("===========================================");
    log_info("  MWAN Tunnel Forwarding Started");
    log_info("  Mode: Simple L3 Forwarding (No Frag/Reasm/Reorder)");
    log_info("  Workers: %d outbound + %d inbound = %d total",
             total_out, total_in, total_threads);
    log_info("  OUTBOUND: %s -> TUNNEL[0..%zu] (RR)",
             ctx.cfg.local_if, ctx.cfg.ne_tunnel_count - 1);
    log_info("  INBOUND:  TUNNEL[0..%zu] -> %s",
             ctx.cfg.ne_tunnel_count - 1, ctx.cfg.local_if);
    log_info("  Press Ctrl+C to stop.");
    log_info("===========================================");

    /* Wait for all threads */
    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);

    log_info("Cleaning up...");

    /* ---------- CLEANUP ---------- */

    tc_ingress_cleanup(ctx.cfg.local_if);
    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++)
        tc_wan_ingress_cleanup(ctx.cfg.ne_tunnels[w].ifname);

cleanup_inbound:
    for (size_t w = 0; w < in_worker_count; w++)
        worker_close(&in_workers[w]);

    afpkt_fanout_close(&fg_out);

cleanup_route:
    system_del_route_dev(ctx.cfg.remote_cidr, ctx.cfg.local_if);

    /* Restore IP forward to original state */
    system_restore_ip_forward();

    netdev_reset_interface(ctx.cfg.local_if);
    for (size_t i = 0; i < ctx.cfg.wan_count; i++)
        netdev_reset_interface(ctx.cfg.wans[i].ifname);

    log_info("Cleanup done.");
    return 0;
}
