#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"

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
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--node") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            node_id = argv[++i];
        } else if (strcmp(argv[i], "--dump-config") == 0) {
            dump = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            log_error("Unknown argument: %s", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!config_path || !node_id) {
        usage(argv[0]);
        return 2;
    }

    /* ---- load config ---- */
    app_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (app_context_init(&ctx, config_path, node_id) != 0) {
        log_error("Failed to load config");
        return 1;
    }

    if (dump) {
        app_context_dump(&ctx);
    }

    g_ctx = &ctx;

    /* ---- STEP 1: enable ip_forward ---- */
    if (system_enable_ip_forward() != 0) {
        log_error("Failed to enable IP forwarding");
        return 1;
    }

    /* ---- STEP 2: force routing into TC ---- */
    if (system_add_route_dev(ctx.cfg.remote_cidr,
                             ctx.cfg.local_if) != 0) {
        log_error("Failed to add route for %s via %s",
                  ctx.cfg.remote_cidr,
                  ctx.cfg.local_if);
        return 1;
    }

    /* ===================================================== */
    /* ==== OUTBOUND: create veth_tx pair ================== */
    /* ===================================================== */

    const char *veth_tx_in  = "veth_tx_in";
    const char *veth_tx_out = "veth_tx_out";

    if (netdev_create_veth_pair(veth_tx_in, veth_tx_out, 1500) != 0) {
        log_error("Failed to create veth_tx pair");
        goto cleanup_route;
    }

    /* TC ingress on LOCAL_IF -> veth_tx_out */
    if (tc_ingress_redirect(ctx.cfg.local_if, veth_tx_out) != 0) {
        log_error("Failed to redirect ingress traffic to %s", veth_tx_out);
        goto cleanup_veth_tx;
    }

    /* TC egress redirect veth_tx_in -> WAN0 */
    if (tc_egress_redirect(veth_tx_in, ctx.cfg.wans[0].ifname) != 0) {
        log_error("Failed to setup TC egress redirect");
        goto cleanup_tc_ingress_local;
    }

    /* ===================================================== */
    /* ==== INBOUND: create veth_rx pair =================== */
    /* ===================================================== */

    const char *veth_rx_in  = "veth_rx_in";
    const char *veth_rx_out = "veth_rx_out";

    if (netdev_create_veth_pair(veth_rx_in, veth_rx_out, 1500) != 0) {
        log_error("Failed to create veth_rx pair");
        goto cleanup_tc_egress;
    }

    /* TC ingress on WAN[0] with filter src REMOTE_CIDR -> veth_rx_out */
    if (tc_wan_ingress_redirect_cidr(ctx.cfg.wans[0].ifname,
                                      veth_rx_out,
                                      ctx.cfg.remote_cidr) != 0) {
        log_error("Failed to setup TC WAN ingress redirect on %s",
                  ctx.cfg.wans[0].ifname);
        goto cleanup_veth_rx;
    }

    /* ===================================================== */
    /* ==== FANOUT: open N workers per direction =========== */
    /* ===================================================== */

    afpkt_fanout_t fg_out;
    if (afpkt_fanout_open(&fg_out, veth_tx_out, 1) != 0) {
        log_error("Failed to open fanout outbound on %s", veth_tx_out);
        goto cleanup_tc_wan_ingress;
    }

    afpkt_fanout_t fg_in;
    if (afpkt_fanout_open(&fg_in, veth_rx_out, 2) != 0) {
        log_error("Failed to open fanout inbound on %s", veth_rx_out);
        goto cleanup_fanout_out;
    }

    /* ===================================================== */
    /* ==== INIT CACHE ===================================== */
    /* ===================================================== */

    afpkt_fanout_init_cache_outbound(&fg_out, &ctx);
    afpkt_fanout_init_cache_inbound(&fg_in, &ctx);

    /* ===================================================== */
    /* ==== START THREADS ================================== */
    /* ===================================================== */

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int total_threads = NUM_WORKERS * 2;
    pthread_t threads[NUM_WORKERS * 2];
    worker_thread_arg_t args[NUM_WORKERS * 2];

    for (int i = 0; i < NUM_WORKERS; i++) {
        /* Outbound worker */
        args[i] = (worker_thread_arg_t){
            .worker      = &fg_out.workers[i],
            .fg          = &fg_out,
            .ctx         = &ctx,
            .running     = &running,
            .is_outbound = 1,
        };
        if (pthread_create(&threads[i], NULL, worker_fn, &args[i]) != 0) {
            log_error("Failed to create outbound worker thread %d", i);
            running = 0;
            for (int k = 0; k < i; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_fanout_in;
        }

        /* Inbound worker */
        int j = NUM_WORKERS + i;
        args[j] = (worker_thread_arg_t){
            .worker      = &fg_in.workers[i],
            .fg          = &fg_in,
            .ctx         = &ctx,
            .running     = &running,
            .is_outbound = 0,
        };
        if (pthread_create(&threads[j], NULL, worker_fn, &args[j]) != 0) {
            log_error("Failed to create inbound worker thread %d", i);
            running = 0;
            for (int k = 0; k <= i; k++)
                pthread_join(threads[k], NULL);
            for (int k = NUM_WORKERS; k < j; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_fanout_in;
        }
    }

    log_info("===========================================");
    log_info("  PACKET_FANOUT forwarding started");
    log_info("  Workers: %d outbound + %d inbound = %d total",
             NUM_WORKERS, NUM_WORKERS, total_threads);
    log_info("  OUTBOUND: %s -> WAN[0..%zu]",
             ctx.cfg.local_if, ctx.cfg.wan_count - 1);
    log_info("  INBOUND:  WAN[0] (%s) -> %s",
             ctx.cfg.wans[0].ifname, ctx.cfg.local_if);
    log_info("  Press Ctrl+C to stop.");
    log_info("===========================================");

    /* Wait for all threads */
    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);

    log_info("Cleaning up...");

    /* ---------- CLEANUP ---------- */
cleanup_fanout_in:
    afpkt_fanout_close(&fg_in);

cleanup_fanout_out:
    afpkt_fanout_close(&fg_out);

cleanup_tc_wan_ingress:
    tc_wan_ingress_cleanup(ctx.cfg.wans[0].ifname);

cleanup_veth_rx:
    netdev_delete(veth_rx_in);

cleanup_tc_egress:
    tc_egress_cleanup(veth_tx_in);

cleanup_tc_ingress_local:
    tc_ingress_cleanup(ctx.cfg.local_if);

cleanup_veth_tx:
    netdev_delete(veth_tx_in);

cleanup_route:
    system_del_route_dev(ctx.cfg.remote_cidr,
                         ctx.cfg.local_if);

    log_info("Cleanup done.");

    return 0;
}
