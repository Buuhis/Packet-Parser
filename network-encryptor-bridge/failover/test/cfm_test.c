#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>
#include "cfm_diag.h"

#define MAX_INTERFACES 16
#define MAC_LEN 6

struct wan_config {
    char ifname[IFNAMSIZ];
    uint32_t dst_ip;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    int dataplane;
};

struct app_config {
    struct wan_config wans[MAX_INTERFACES];
    int wan_count;
};

static volatile bool keep_running = true;

int fwd_wan_is_stopped(int dp) {
    (void)dp;
    return 0;
}

static void handle_signal(int sig) {
    (void)sig;
    keep_running = false;
}

static const char *state_to_str(int state) {
    switch (state) {
        case CFM_LINK_STATE_INIT: return "-";
        case CFM_LINK_STATE_UP:   return "UP";
        case CFM_LINK_STATE_DOWN: return "DOWN";
        default:                  return "?";
    }
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

    int last_state1 = cfm_get_link_state(0);
    int last_state2 = cfm_get_link_state(1);

    printf("[CFM-TEST] Initial Link Status:\n");
    printf("           %s: %s\n", wan1, state_to_str(last_state1));
    printf("           %s: %s\n", wan2, state_to_str(last_state2));

    int print_counter = 0;
    while (keep_running) {
        usleep(100000); // Check every 100ms
        print_counter++;

        int state1 = cfm_get_link_state(0);
        int state2 = cfm_get_link_state(1);

        if (state1 != last_state1) {
            printf("[CFM-TEST] STATUS CHANGE -> Interface %s: %s -> %s\n", 
                   wan1, state_to_str(last_state1), state_to_str(state1));
            last_state1 = state1;
        }

        if (state2 != last_state2) {
            printf("[CFM-TEST] STATUS CHANGE -> Interface %s: %s -> %s\n", 
                   wan2, state_to_str(last_state2), state_to_str(state2));
            last_state2 = state2;
        }

        if (print_counter >= 10) {
            print_counter = 0;
            y1731_metrics_t m1, m2;
            if (cfm_get_link_quality(0, &m1) == 0 && state1 == CFM_LINK_STATE_UP) {
                printf("[CFM-TEST] Link %s Quality: RTT = %u us, Jitter = %u us, Loss Rate = %.2f%% (%s)\n",
                       wan1, m1.rtt_us, m1.jitter_us, m1.loss_rate * 100.0f,
                       m1.loss_mechanism == 1 ? "LMM" : "SLM");
            }
            if (cfm_get_link_quality(1, &m2) == 0 && state2 == CFM_LINK_STATE_UP) {
                printf("[CFM-TEST] Link %s Quality: RTT = %u us, Jitter = %u us, Loss Rate = %.2f%% (%s)\n",
                       wan2, m2.rtt_us, m2.jitter_us, m2.loss_rate * 100.0f,
                       m2.loss_mechanism == 1 ? "LMM" : "SLM");
            }
        }
    }

    printf("\n[CFM-TEST] Stopping CFM subsystem and cleaning up...\n");
    cfm_cleanup();
    printf("[CFM-TEST] Exited cleanly.\n");

    return EXIT_SUCCESS;
}
