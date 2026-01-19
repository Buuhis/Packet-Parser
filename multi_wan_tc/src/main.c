#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
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
        "Usage: %s --config <file> [--dump-config]\n", prog);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;
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

    if (!config_path) {
        usage(argv[0]);
        return 2;
    }

    /* ---- load config ---- */
    app_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (app_context_init(&ctx, config_path) != 0) {
        log_error("Failed to load config");
        return 1;
    }

    if (dump) {
        app_context_dump(&ctx);
    }

    g_ctx = &ctx;

    /* ---- STEP 2: enable ip_forward ---- */
    if (system_enable_ip_forward() != 0) {
        log_error("Failed to enable IP forwarding");
        return 1;
    }

    /* ---- STEP 3: force routing into TC ---- */
    if (system_add_route_dev(ctx.cfg.remote_cidr,
                             ctx.cfg.local_if) != 0) {
        log_error("Failed to add route for %s via %s",
                  ctx.cfg.remote_cidr,
                  ctx.cfg.local_if);
        return 1;
    }

    /* ===================================================== */
    /* ==== STEP 3.5: 7A-A1 – create veth for userspace ==== */
    /* ===================================================== */

    const char *veth_in  = "veth_tx_in";
    const char *veth_out = "veth_tx_out";

    if (netdev_create_veth_pair(veth_in, veth_out, 1500) != 0) {
        log_error("Failed to create veth pair");
        goto cleanup_route;
    }

    /* ===================================================== */
    /* ==== STEP 3.6: 7A-A2 – TC ingress → veth_tx_in ====== */
    /* ===================================================== */

    if (tc_ingress_redirect(ctx.cfg.local_if, veth_in) != 0) {
        log_error("Failed to redirect ingress traffic to %s", veth_in);
        goto cleanup_veth;
    }

    /* ---- STEP 4: TC root qdisc on veth_tx_in ---- */
    if (tc_add_root_qdisc(veth_in) != 0) {
        log_error("Failed to attach TC root qdisc on %s", veth_in);
        goto cleanup_tc_ingress;
    }

    /* ---- STEP 5: create WAN classes ---- */
    for (size_t i = 0; i < ctx.cfg.wan_count; i++) {
        int class_minor = (int)(i + 1) * 10;  /* 10, 20, 30 */
        if (tc_add_class(veth_in, 1, class_minor) != 0) {
            log_error("Failed to add TC class %d:%d",
                      1, class_minor);
            goto cleanup_tc;
        }
    }

    /* ---- STEP 6: redirect ALL traffic to WAN0 (test) ---- */
    tc_del_filters(veth_in);

    if (tc_add_redirect_filter(veth_in,
                               ctx.cfg.remote_cidr,
                               10,                      /* class 1:10 */
                               ctx.cfg.wans[0].ifname)  /* WAN0 */
        != 0) {
        log_error("Failed to add redirect filter");
        goto cleanup_tc;
    }

    /* ---- install signal handlers ---- */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    log_info("Press Ctrl+C to stop.");

    /* ---- RUN LOOP (control-plane placeholder) ---- */
    while (running) {
        sleep(1);
    }

    log_info("Cleaning up...");

    /* ---------- CLEANUP (FAIL-OPEN) ---------- */
cleanup_tc_ingress:
    tc_ingress_cleanup(ctx.cfg.local_if);

cleanup_veth:
    netdev_delete(veth_in);

cleanup_tc:
    tc_del_filters(veth_in);
    tc_del_root_qdisc(veth_in);

cleanup_route:
    system_del_route_dev(ctx.cfg.remote_cidr,
                         ctx.cfg.local_if);

    log_info("Cleanup done.");

    return 0;
}

