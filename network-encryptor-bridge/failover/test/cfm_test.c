#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include "cfm_diag.h"
#include "config.h"

static volatile bool keep_running = true;

int fwd_wan_is_stopped(int dp) {
    (void)dp;
    return 0;
}

static void handle_signal(int sig) {
    (void)sig;
    keep_running = false;
}

int main(int argc, char *argv[]) {
    char wan1[IFNAMSIZ] = "eth1";
    char wan2[IFNAMSIZ] = "eth2";

    if (argc >= 3) {
        strncpy(wan1, argv[1], IFNAMSIZ - 1);
        strncpy(wan2, argv[2], IFNAMSIZ - 1);
    } else if (argc == 2) {
        strncpy(wan1, argv[1], IFNAMSIZ - 1);
    }

    printf("[CFM-TEST] Starting L2 CFM test on interfaces: %s, %s\n", wan1, wan2);
    printf("[CFM-TEST] Press Ctrl+C or kill the process to stop.\n");

    // Set up signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Build mock config
    struct app_config cfg;
    memset(&cfg, 0, sizeof(cfg));

    // Configure WAN 1
    strncpy(cfg.wans[0].ifname, wan1, IFNAMSIZ - 1);
    cfg.wans[0].dataplane = 1;
    cfg.wans[0].dst_ip = 0; // Ensures CFM monitors it

    // Configure WAN 2
    strncpy(cfg.wans[1].ifname, wan2, IFNAMSIZ - 1);
    cfg.wans[1].dataplane = 1;
    cfg.wans[1].dst_ip = 0; // Ensures CFM monitors it

    cfg.wan_count = 2;

    // Initialize CFM
    if (cfm_init(&cfg) != 0) {
        fprintf(stderr, "[CFM-TEST] Failed to initialize CFM subsystem\n");
        return EXIT_FAILURE;
    }

    printf("[CFM-TEST] CFM initialized successfully. Monitoring link status...\n");

    bool last_status1 = cfm_is_link_up(0);
    bool last_status2 = cfm_is_link_up(1);

    printf("[CFM-TEST] Initial Link Status:\n");
    printf("           %s: %s\n", wan1, last_status1 ? "UP" : "DOWN");
    printf("           %s: %s\n", wan2, last_status2 ? "UP" : "DOWN");

    while (keep_running) {
        usleep(100000); // Check every 100ms

        bool status1 = cfm_is_link_up(0);
        bool status2 = cfm_is_link_up(1);

        if (status1 != last_status1) {
            printf("[CFM-TEST] STATUS CHANGE -> Interface %s is now: %s\n", wan1, status1 ? "UP" : "DOWN");
            last_status1 = status1;
        }

        if (status2 != last_status2) {
            printf("[CFM-TEST] STATUS CHANGE -> Interface %s is now: %s\n", wan2, status2 ? "UP" : "DOWN");
            last_status2 = status2;
        }
    }

    printf("\n[CFM-TEST] Stopping CFM subsystem and cleaning up...\n");
    cfm_cleanup();
    printf("[CFM-TEST] Exited cleanly.\n");

    return EXIT_SUCCESS;
}
