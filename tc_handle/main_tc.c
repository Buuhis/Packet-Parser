/*
 * TC-based Multi-WAN Load Balancer
 *
 * Architecture:
 *   - Control Plane: This C program (configuration, monitoring, policy updates)
 *   - Data Plane: Linux TC (Traffic Control) in kernel space
 *
 * Flow:
 *   CLIENT -> [LOCAL interface] -> [Kernel routing + TC] -> [WAN 1/2/3...] -> SERVER
 *
 * The program does NOT handle packets directly. Instead, it:
 *   1. Configures multipath routing with nexthop groups
 *   2. Sets up TC qdiscs and filters for traffic steering
 *   3. Monitors WAN health and updates routing dynamically
 *   4. Collects and reports statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "tc_lb.h"

static lb_config_t g_config;

void signal_handler(int sig) {
    (void)sig;
    printf("\n[MAIN] Received signal, shutting down...\n");
    g_config.running = false;
}

void print_banner(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║     TC-based Multi-WAN Load Balancer (Control Plane)       ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  - Data plane: Linux TC + Multipath Routing (in kernel)    ║\n");
    printf("║  - Control plane: WAN monitoring, Policy updates           ║\n");
    printf("║  - Load balancing: Round-robin / Hash-flow                 ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(const char *prog) {
    printf("Usage: %s <config_file>\n", prog);
    printf("\nConfig file format:\n");
    printf("  local <interface>                    # Local interface (facing clients)\n");
    printf("  remote <network/prefix>              # Remote network to load balance\n");
    printf("  wan <interface> <gateway> [peer_ip]  # WAN interface with gateway\n");
    printf("  method <roundrobin|hash>             # Load balance method (optional)\n");
    printf("\nExample config:\n");
    printf("  local eth0\n");
    printf("  remote 192.168.2.0/24\n");
    printf("  wan eth1 10.0.1.1 8.8.8.8\n");
    printf("  wan eth2 10.0.2.1 8.8.8.8\n");
    printf("  wan eth3 10.0.3.1 8.8.8.8\n");
    printf("  method roundrobin\n");
}

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Load configuration
    printf("[MAIN] Loading configuration from %s\n", argv[1]);
    if (config_load(&g_config, argv[1]) != 0) {
        fprintf(stderr, "[MAIN] Failed to load configuration\n");
        return 1;
    }
    config_print(&g_config);

    // Enable IP forwarding
    printf("[MAIN] Setting up system...\n");
    if (system_setup_ip_forwarding(true) != 0) {
        fprintf(stderr, "[MAIN] Failed to enable IP forwarding\n");
        return 1;
    }

    // Setup routing tables for each WAN
    if (system_setup_routing_tables(&g_config) != 0) {
        fprintf(stderr, "[MAIN] Warning: Failed to setup some routing tables\n");
        // Continue anyway
    }

    // Setup TC load balancing
    printf("[MAIN] Setting up TC load balancing...\n");
    if (tc_setup_load_balance(&g_config) != 0) {
        fprintf(stderr, "[MAIN] Failed to setup TC load balancing\n");
        goto cleanup;
    }

    // Create monitoring threads
    pthread_t wan_monitor_tid;
    pthread_t stats_tid;

    printf("[MAIN] Starting monitoring threads...\n");

    if (pthread_create(&wan_monitor_tid, NULL, wan_monitor_thread, &g_config) != 0) {
        fprintf(stderr, "[MAIN] Failed to create WAN monitor thread\n");
        goto cleanup;
    }

    if (pthread_create(&stats_tid, NULL, stats_collector_thread, &g_config) != 0) {
        fprintf(stderr, "[MAIN] Failed to create stats collector thread\n");
        g_config.running = false;
        pthread_join(wan_monitor_tid, NULL);
        goto cleanup;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Load balancer is running. Press Ctrl+C to stop.          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Main loop - just wait for threads
    while (g_config.running) {
        sleep(1);
    }

    // Wait for threads to finish
    printf("[MAIN] Waiting for threads to finish...\n");
    pthread_join(wan_monitor_tid, NULL);
    pthread_join(stats_tid, NULL);

cleanup:
    // Cleanup
    printf("[MAIN] Cleaning up...\n");
    tc_cleanup(&g_config);
    system_cleanup_routing_tables(&g_config);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Shutdown complete.                                        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    return 0;
}
