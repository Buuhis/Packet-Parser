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

/* ---------- global state ---------- */

static volatile int running = 1;
static app_context_t *g_ctx = NULL;

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

typedef struct {
    afpkt_worker_t       *worker;
    const afpkt_fanout_t *fg;
    app_context_t        *ctx;
    volatile int         *running;
    int                   is_outbound;
    reorder_ctx_t        *reorder;   /* inbound only */
} worker_thread_arg_t;

static void *worker_fn(void *arg)
{
    worker_thread_arg_t *a = (worker_thread_arg_t *)arg;
    if (a->is_outbound)
        afpkt_worker_loop_outbound(a->worker, a->fg, a->ctx, a->running);
    else
        afpkt_worker_loop_inbound(a->worker, a->fg, a->ctx, a->running, a->reorder);
    return NULL;
}

/* ---------- reorder output thread arg ---------- */

static void *reorder_thread_fn(void *arg)
{
    reorder_ctx_t *ctx = (reorder_ctx_t *)arg;
    reorder_output_loop(ctx);
    return NULL;
}

/* ---------- helper: close single worker ---------- */

static void worker_close(afpkt_worker_t *w)
{
    if (w->ring) {
        munmap(w->ring, w->ring_size);
        w->ring = NULL;
    }
    if (w->tx_fd >= 0) { close(w->tx_fd); w->tx_fd = -1; }
    if (w->rx_fd >= 0) { close(w->rx_fd); w->rx_fd = -1; }
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *node_id = NULL;
    int dump = 0;

    log_set_level(LOG_INFO);

    /* ---- parse args ---- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--node") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            node_id = argv[++i];
        } else if (strcmp(argv[i], "--dump-config") == 0) {
            dump = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        } else {
            log_error("Unknown argument: %s", argv[i]);
            usage(argv[0]); return 2;
        }
    }

    if (!config_path || !node_id) { usage(argv[0]); return 2; }

    /* ---- load config ---- */
    app_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (app_context_init(&ctx, config_path, node_id) != 0) {
        log_error("Failed to load config");
        return 1;
    }

    if (dump) app_context_dump(&ctx);
    g_ctx = &ctx;

    if (ctx.cfg.ne_tunnel_count == 0) {
        log_error("No ne_tunnel defined for node %s", node_id);
        return 1;
    }

    /* ---- STEP 1: enable ip_forward ---- */
    if (system_enable_ip_forward() != 0) {
        log_error("Failed to enable IP forwarding");
        return 1;
    }

    /* ---- STEP 2: force routing into TC ---- */
    if (system_add_route_dev(ctx.cfg.remote_cidr, ctx.cfg.local_if) != 0) {
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
    if (afpkt_fanout_open(&fg_out, ctx.cfg.local_if, 1) != 0) {
        log_error("Failed to open fanout outbound on %s", ctx.cfg.local_if);
        goto cleanup_route;
    }

    /* ===================================================== */
    /* ==== INBOUND: 1 single socket per ne_tunnel ========= */
    /* ===================================================== */

    afpkt_worker_t in_workers[MAX_NE_TUNNELS];
    size_t in_worker_count = 0;
    memset(in_workers, 0, sizeof(in_workers));
    for (size_t i = 0; i < MAX_NE_TUNNELS; i++) {
        in_workers[i].rx_fd = -1;
        in_workers[i].tx_fd = -1;
    }

    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++) {
        in_workers[w].id = (int)w;
        if (afpkt_single_open(&in_workers[w], ctx.cfg.ne_tunnels[w].ifname) != 0) {
            log_error("Failed to open inbound on %s", ctx.cfg.ne_tunnels[w].ifname);
            goto cleanup_inbound;
        }
        in_worker_count++;
    }

    /* ===================================================== */
    /* ==== TC DROP: Prevent kernel from double processing = */
    /* ===================================================== */

    /* Outbound: Drop packets from local going to remote CIDR */
    if (tc_ingress_drop_cidr(ctx.cfg.local_if, ctx.cfg.remote_cidr) != 0)
        log_warn("Failed to setup TC ingress drop on %s", ctx.cfg.local_if);

    /* Inbound: Drop mwan protocol packets on ne_tunnel interfaces */
    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++) {
        if (tc_wan_ingress_drop_cidr(ctx.cfg.ne_tunnels[w].ifname, ctx.cfg.remote_cidr) != 0)
            log_warn("Failed to setup TC drop on %s", ctx.cfg.ne_tunnels[w].ifname);
    }

    /* ===================================================== */
    /* ==== INIT CACHES ==================================== */
    /* ===================================================== */

    afpkt_fanout_init_cache_outbound(&fg_out, &ctx);
    /* Inbound cache: we need local_if info for the reorder output thread */
    /* Use fg_out.local for convenience (init it here) */
    afpkt_fanout_init_cache_inbound(&fg_out, &ctx);

    /* ===================================================== */
    /* ==== REORDER CONTEXT ================================ */
    /* ===================================================== */

    reorder_ctx_t reorder;
    reorder_init(&reorder);
    reorder.running = &running;

    /* TX socket for reorder output thread */
    reorder.tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (reorder.tx_fd < 0) {
        log_error("Failed to create reorder TX socket: %s", strerror(errno));
        goto cleanup_tc;
    }

    reorder.local_ifindex = fg_out.local.ifindex;
    memcpy(reorder.local_src_mac, fg_out.local.src_mac, 6);
    memcpy(reorder.lan_dst_mac, ctx.cfg.lan.dst_mac, 6);

    /* ===================================================== */
    /* ==== START THREADS ================================== */
    /* ===================================================== */

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int total_out = NUM_WORKERS;
    int total_in  = (int)ctx.cfg.ne_tunnel_count;
    int total_threads = total_out + total_in + 1;  /* +1 for reorder output */

    pthread_t threads[NUM_WORKERS + MAX_NE_TUNNELS + 1];
    worker_thread_arg_t args[NUM_WORKERS + MAX_NE_TUNNELS];
    int tidx = 0;

    /* Outbound workers (fanout on local_if) */
    for (int i = 0; i < NUM_WORKERS; i++) {
        args[tidx] = (worker_thread_arg_t){
            .worker      = &fg_out.workers[i],
            .fg          = &fg_out,
            .ctx         = &ctx,
            .running     = &running,
            .is_outbound = 1,
            .reorder     = NULL,
        };
        if (pthread_create(&threads[tidx], NULL, worker_fn, &args[tidx]) != 0) {
            log_error("Failed to create outbound worker %d", i);
            running = 0;
            for (int k = 0; k < tidx; k++) pthread_join(threads[k], NULL);
            goto cleanup_reorder;
        }
        tidx++;
    }

    /* Inbound workers (1 per ne_tunnel) */
    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++) {
        args[tidx] = (worker_thread_arg_t){
            .worker      = &in_workers[w],
            .fg          = &fg_out,    /* Used only for local cache */
            .ctx         = &ctx,
            .running     = &running,
            .is_outbound = 0,
            .reorder     = &reorder,
        };
        if (pthread_create(&threads[tidx], NULL, worker_fn, &args[tidx]) != 0) {
            log_error("Failed to create inbound worker tunnel[%zu]", w);
            running = 0;
            for (int k = 0; k < tidx; k++) pthread_join(threads[k], NULL);
            goto cleanup_reorder;
        }
        tidx++;
    }

    /* Reorder output thread */
    if (pthread_create(&threads[tidx], NULL, reorder_thread_fn, &reorder) != 0) {
        log_error("Failed to create reorder output thread");
        running = 0;
        for (int k = 0; k < tidx; k++) pthread_join(threads[k], NULL);
        goto cleanup_reorder;
    }
    tidx++;

    log_info("===========================================");
    log_info("  MWAN Tunnel Forwarding Started");
    log_info("  Architecture: Fragment + Reassembly + Reorder");
    log_info("  Threshold: %d bytes (no-frag), Tunnel MTU: %d",
             MWAN_FRAG_THRESHOLD, MWAN_NE_TUNNEL_MTU);
    log_info("  Workers: %d outbound + %d inbound + 1 reorder = %d total",
             total_out, total_in, total_threads);
    log_info("  OUTBOUND: %s -> TUNNEL[0..%zu] (RR by seq)",
             ctx.cfg.local_if, ctx.cfg.ne_tunnel_count - 1);
    log_info("  INBOUND:  TUNNEL[0..%zu] -> reassemble -> reorder -> %s",
             ctx.cfg.ne_tunnel_count - 1, ctx.cfg.local_if);
    log_info("  Press Ctrl+C to stop.");
    log_info("===========================================");

    /* Wait for all threads */
    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);

    log_info("Cleaning up...");

    /* ---------- CLEANUP ---------- */
cleanup_reorder:
    if (reorder.tx_fd >= 0) {
        close(reorder.tx_fd);
        reorder.tx_fd = -1;
    }

cleanup_tc:
    tc_ingress_cleanup(ctx.cfg.local_if);
    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++)
        tc_wan_ingress_cleanup(ctx.cfg.ne_tunnels[w].ifname);

cleanup_inbound:
    for (size_t w = 0; w < in_worker_count; w++)
        worker_close(&in_workers[w]);

    afpkt_fanout_close(&fg_out);

cleanup_route:
    system_del_route_dev(ctx.cfg.remote_cidr, ctx.cfg.local_if);

    netdev_reset_interface(ctx.cfg.local_if);
    for (size_t i = 0; i < ctx.cfg.wan_count; i++)
        netdev_reset_interface(ctx.cfg.wans[i].ifname);

    log_info("Cleanup done.");
    return 0;
}
