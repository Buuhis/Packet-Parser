#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"
#include "userio/afpkt_multithread.h"  /* NEW: Multi-threaded API */

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
    log_info("Received signal %d, shutting down...", sig);
    running = 0;
}

/* ---------- usage ---------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --config <file> --node <id> [--dump-config] [--multithread]\n"
        "\n"
        "Options:\n"
        "  --config <file>    Path to configuration file\n"
        "  --node <id>        Node ID\n"
        "  --dump-config      Dump configuration and exit\n"
        "  --multithread      Use multi-threaded mode (10 workers per direction)\n"
        "  --help             Show this help message\n",
        prog);
}

/* ---------- thread args (for single-threaded mode) ---------- */

typedef struct {
    int fd;
    app_context_t *ctx;
} thread_arg_t;

/* ---------- outbound thread (LOCAL -> WAN) - Single-threaded mode ---------- */

static void *outbound_thread(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    log_info("Outbound thread started (LOCAL -> WAN) - Single-threaded mode");

    while (running) {
        afpkt_poll_and_forward(targ->fd, targ->ctx);
    }

    log_info("Outbound thread stopped");
    return NULL;
}

/* ---------- inbound thread (WAN -> LOCAL) - Single-threaded mode ---------- */

static void *inbound_thread(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    log_info("Inbound thread started (WAN -> LOCAL) - Single-threaded mode");

    while (running) {
        afpkt_poll_and_forward_inbound(targ->fd, targ->ctx);
    }

    log_info("Inbound thread stopped");
    return NULL;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *node_id = NULL;
    int dump = 0;
    int use_multithread = 0;  /* NEW: Flag for multi-threaded mode */

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
        } else if (strcmp(argv[i], "--multithread") == 0) {
            use_multithread = 1;  /* NEW */
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
    /* ==== INIT CACHE ===================================== */
    /* ===================================================== */
    afpkt_init_cache(&ctx);

    /* install signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* ===================================================== */
    /* ==== START PACKET FORWARDING ======================== */
    /* ===================================================== */

    if (use_multithread) {
        /* ============================================== */
        /* MULTI-THREADED MODE (10 workers per direction) */
        /* ============================================== */
        
        log_info("===========================================");
        log_info("  MULTI-THREADED MODE ENABLED");
        log_info("  10 workers for OUTBOUND (LOCAL -> WAN)");
        log_info("  10 workers for INBOUND (WAN -> LOCAL)");
        log_info("===========================================");

        /* Initialize outbound workers (LOCAL -> WAN) */
        if (afpkt_multithread_init(veth_tx_out, &ctx, 0) != 0) {
            log_error("Failed to initialize outbound workers");
            goto cleanup_tc_wan_ingress;
        }

        /* Initialize inbound workers (WAN -> LOCAL) */
        if (afpkt_multithread_init(veth_rx_out, &ctx, 1) != 0) {
            log_error("Failed to initialize inbound workers");
            afpkt_multithread_cleanup();  /* Cleanup outbound workers */
            goto cleanup_tc_wan_ingress;
        }

        log_info("===========================================");
        log_info("  Bidirectional forwarding started");
        log_info("  OUTBOUND: %s -> WAN[0] (%s) [10 workers]",
                 ctx.cfg.local_if, ctx.cfg.wans[0].ifname);
        log_info("  INBOUND:  WAN[0] (%s) -> %s [10 workers]",
                 ctx.cfg.wans[0].ifname, ctx.cfg.local_if);
        log_info("  Press Ctrl+C to stop.");
        log_info("===========================================");

        /* Main loop: Print statistics every 5 seconds */
        while (running) {
            sleep(5);
            if (running) {
                afpkt_multithread_print_stats();
            }
        }

        /* Cleanup workers */
        log_info("Stopping workers...");
        afpkt_multithread_cleanup();

    } else {
        /* ============================================== */
        /* SINGLE-THREADED MODE (1 thread per direction) */
        /* ============================================== */
        
        log_info("===========================================");
        log_info("  SINGLE-THREADED MODE");
        log_info("===========================================");

        /* Open AF_PACKET RX on veth_tx_out */
        int tx_fd = afpkt_open_rx(veth_tx_out);
        if (tx_fd < 0) {
            log_error("Failed to open AF_PACKET RX for outbound");
            goto cleanup_tc_wan_ingress;
        }

        /* Open AF_PACKET RX on veth_rx_out */
        int rx_fd = afpkt_open_rx_inbound(veth_rx_out);
        if (rx_fd < 0) {
            log_error("Failed to open AF_PACKET RX for inbound");
            afpkt_close(tx_fd);
            goto cleanup_tc_wan_ingress;
        }

        pthread_t thread_out, thread_in;
        thread_arg_t arg_out = { .fd = tx_fd, .ctx = &ctx };
        thread_arg_t arg_in  = { .fd = rx_fd, .ctx = &ctx };

        if (pthread_create(&thread_out, NULL, outbound_thread, &arg_out) != 0) {
            log_error("Failed to create outbound thread");
            afpkt_close(tx_fd);
            afpkt_close_inbound(rx_fd);
            goto cleanup_tc_wan_ingress;
        }

        if (pthread_create(&thread_in, NULL, inbound_thread, &arg_in) != 0) {
            log_error("Failed to create inbound thread");
            running = 0;
            pthread_join(thread_out, NULL);
            afpkt_close(tx_fd);
            afpkt_close_inbound(rx_fd);
            goto cleanup_tc_wan_ingress;
        }

        log_info("===========================================");
        log_info("  Bidirectional forwarding started");
        log_info("  OUTBOUND: %s -> WAN[0] (%s)",
                 ctx.cfg.local_if, ctx.cfg.wans[0].ifname);
        log_info("  INBOUND:  WAN[0] (%s) -> %s",
                 ctx.cfg.wans[0].ifname, ctx.cfg.local_if);
        log_info("  Press Ctrl+C to stop.");
        log_info("===========================================");

        /* Wait for threads */
        pthread_join(thread_out, NULL);
        pthread_join(thread_in, NULL);

        /* Cleanup */
        afpkt_close_inbound(rx_fd);
        afpkt_close(tx_fd);
    }

    log_info("Cleaning up...");

    /* ---------- CLEANUP ---------- */
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
