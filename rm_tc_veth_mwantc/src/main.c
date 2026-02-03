#include "app_context.h"
#include "system/system.h"
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
static int saved_ip_forward = -1;

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

    /* ===================================================== */
    /* ==== STEP 1: Disable ip_forward ===================== */
    /* ===================================================== */
    /* Save current state so we can restore on cleanup.
     * With ip_forward=0, kernel will NOT forward any packets.
     * AF_PACKET still captures all incoming packets.
     * Our workers handle all forwarding in userspace. */

    saved_ip_forward = system_get_ip_forward();

    if (system_disable_ip_forward() != 0) {
        log_error("Failed to disable IP forwarding");
        return 1;
    }

    /* ===================================================== */
    /* ==== STEP 2: Disable GRO/GSO/TSO ==================== */
    /* ===================================================== */
    /* Without this, GRO aggregates TCP segments into 64KB
     * super-packets. AF_PACKET captures the 64KB packet,
     * sendto() to WAN (MTU=1500) fails with EMSGSIZE. */

    netdev_disable_offloads(ctx.cfg.local_if);

    for (size_t i = 0; i < ctx.cfg.wan_count; i++)
        netdev_disable_offloads(ctx.cfg.wans[i].ifname);

    /* ===================================================== */
    /* ==== STEP 3: AF_PACKET FANOUT — bind directly ======= */
    /* ===================================================== */
    /* No veth, no TC. AF_PACKET binds directly to NIC.
     * PACKET_IGNORE_OUTGOING prevents capturing our own TX. */

    afpkt_fanout_t fg_out;
    if (afpkt_fanout_open(&fg_out, ctx.cfg.local_if, 1) != 0) {
        log_error("Failed to open fanout outbound on %s", ctx.cfg.local_if);
        goto cleanup_ip_forward;
    }

    afpkt_fanout_t fg_in;
    if (afpkt_fanout_open(&fg_in, ctx.cfg.wans[0].ifname, 2) != 0) {
        log_error("Failed to open fanout inbound on %s", ctx.cfg.wans[0].ifname);
        goto cleanup_fanout_out;
    }

    /* ===================================================== */
    /* ==== STEP 4: Init cache ============================= */
    /* ===================================================== */

    afpkt_fanout_init_cache_outbound(&fg_out, &ctx);
    afpkt_fanout_init_cache_inbound(&fg_in, &ctx);

    /* ===================================================== */
    /* ==== STEP 5: Start threads ========================== */
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
    log_info("  Direct AF_PACKET forwarding started");
    log_info("  Workers: %d outbound + %d inbound = %d total",
             NUM_WORKERS, NUM_WORKERS, total_threads);
    log_info("  OUTBOUND: %s -> WAN[0..%zu]",
             ctx.cfg.local_if, ctx.cfg.wan_count - 1);
    log_info("  INBOUND:  WAN[0] (%s) -> %s",
             ctx.cfg.wans[0].ifname, ctx.cfg.local_if);
    log_info("  ip_forward=0 (kernel forwarding disabled)");
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

cleanup_ip_forward:
    /* Restore ip_forward to its original state */
    if (saved_ip_forward == 1)
        system_enable_ip_forward();

    log_info("Cleanup done.");

    return 0;
}
