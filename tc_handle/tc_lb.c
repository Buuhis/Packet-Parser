#include "tc_lb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>

// ============== Utility Functions ==============

uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

const char* wan_state_str(wan_state_t state) {
    switch (state) {
        case WAN_STATE_UP:       return "UP";
        case WAN_STATE_DOWN:     return "DOWN";
        case WAN_STATE_CHECKING: return "CHECKING";
        default:                 return "UNKNOWN";
    }
}

const char* lb_method_str(lb_method_t method) {
    switch (method) {
        case LB_ROUND_ROBIN:  return "Round Robin";
        case LB_HASH_FLOW:    return "Hash Flow";
        case LB_WEIGHTED_RR:  return "Weighted RR";
        default:              return "Unknown";
    }
}

int run_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret == -1) {
        perror("system() failed");
        return -1;
    }
    return WEXITSTATUS(ret);
}

int run_cmd_output(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen() failed");
        return -1;
    }

    size_t total = 0;
    while (fgets(output + total, output_size - total, fp) != NULL) {
        total = strlen(output);
        if (total >= output_size - 1) break;
    }

    int status = pclose(fp);
    return WEXITSTATUS(status);
}

// ============== Configuration ==============

int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask, int *prefix) {
    char buf[MAX_IP_LEN];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int plen = 24;  // Default prefix

    if (slash) {
        *slash = '\0';
        plen = atoi(slash + 1);
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return -1;
    }

    *network = ntohl(addr.s_addr);
    *mask = plen > 0 ? (0xFFFFFFFF << (32 - plen)) : 0;
    *prefix = plen;

    // Apply mask to get network address
    *network = *network & *mask;

    return 0;
}

int config_load(lb_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("Failed to open config file");
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->lb_method = LB_ROUND_ROBIN;  // Default
    pthread_mutex_init(&cfg->lock, NULL);
    pthread_mutex_init(&cfg->tc_lock, NULL);

    char line[256];
    int table_id = 100;  // Starting table ID for WAN routing

    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\n")] = '\0';

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') continue;

        char key[32], val1[64], val2[64], val3[64];
        int n = sscanf(line, "%31s %63s %63s %63s", key, val1, val2, val3);
        if (n < 2) continue;

        if (strcmp(key, "local") == 0) {
            strncpy(cfg->local_iface, val1, sizeof(cfg->local_iface) - 1);
        }
        else if (strcmp(key, "remote") == 0) {
            strncpy(cfg->remote_cidr, val1, sizeof(cfg->remote_cidr) - 1);
            parse_cidr(val1, &cfg->remote_network, &cfg->remote_mask, &cfg->remote_prefix);
        }
        else if (strcmp(key, "wan") == 0 && cfg->nwan < MAX_WAN) {
            wan_info_t *w = &cfg->wan[cfg->nwan];
            strncpy(w->iface, val1, sizeof(w->iface) - 1);

            // Gateway IP (optional)
            if (n >= 3) {
                strncpy(w->gateway, val2, sizeof(w->gateway) - 1);
            }

            // Peer IP for health check (optional, default to gateway)
            if (n >= 4) {
                strncpy(w->peer_ip, val3, sizeof(w->peer_ip) - 1);
            } else if (n >= 3) {
                strncpy(w->peer_ip, val2, sizeof(w->peer_ip) - 1);
            }

            w->weight = 1;  // Default weight
            w->table_id = table_id++;
            w->state = WAN_STATE_UNKNOWN;
            w->active = true;  // Start as active
            cfg->nwan++;
        }
        else if (strcmp(key, "method") == 0) {
            if (strcmp(val1, "roundrobin") == 0 || strcmp(val1, "rr") == 0) {
                cfg->lb_method = LB_ROUND_ROBIN;
            } else if (strcmp(val1, "hash") == 0) {
                cfg->lb_method = LB_HASH_FLOW;
            } else if (strcmp(val1, "weighted") == 0) {
                cfg->lb_method = LB_WEIGHTED_RR;
            }
        }
    }

    fclose(f);

    if (cfg->nwan == 0) {
        fprintf(stderr, "No WAN interfaces configured\n");
        return -1;
    }

    cfg->active_wan_count = cfg->nwan;
    cfg->running = true;

    return 0;
}

void config_print(const lb_config_t *cfg) {
    printf("\n========== Load Balancer Configuration ==========\n");
    printf("Local interface:    %s\n", cfg->local_iface);
    printf("Remote network:     %s\n", cfg->remote_cidr);
    printf("Load balance method: %s\n", lb_method_str(cfg->lb_method));
    printf("WAN interfaces:     %d\n", cfg->nwan);

    for (int i = 0; i < cfg->nwan; i++) {
        const wan_info_t *w = &cfg->wan[i];
        printf("  WAN%d: %s (gateway: %s, peer: %s, table: %d)\n",
               i, w->iface, w->gateway, w->peer_ip, w->table_id);
    }
    printf("=================================================\n\n");
}

// ============== System Setup ==============

int system_setup_ip_forwarding(bool enable) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "echo %d > /proc/sys/net/ipv4/ip_forward",
             enable ? 1 : 0);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to %s IP forwarding\n", enable ? "enable" : "disable");
        return -1;
    }

    printf("[SYSTEM] IP forwarding %s\n", enable ? "enabled" : "disabled");
    return 0;
}

int system_setup_rp_filter(const char *iface, int value) {
    char cmd[MAX_CMD_LEN];

    // Set for specific interface
    snprintf(cmd, sizeof(cmd), "echo %d > /proc/sys/net/ipv4/conf/%s/rp_filter",
             value, iface);
    run_cmd(cmd);

    // Set for all interfaces
    snprintf(cmd, sizeof(cmd), "echo %d > /proc/sys/net/ipv4/conf/all/rp_filter", value);
    run_cmd(cmd);

    printf("[SYSTEM] rp_filter set to %d for %s\n", value, iface);
    return 0;
}

int system_setup_routing_tables(lb_config_t *cfg) {
    char cmd[MAX_CMD_LEN];

    printf("[SYSTEM] Setting up routing tables...\n");

    for (int i = 0; i < cfg->nwan; i++) {
        wan_info_t *w = &cfg->wan[i];

        if (strlen(w->gateway) == 0) {
            printf("[SYSTEM] WAN%d: No gateway configured, skipping routing table\n", i);
            continue;
        }

        // Flush existing routes in this table
        snprintf(cmd, sizeof(cmd), "ip route flush table %d 2>/dev/null", w->table_id);
        run_cmd(cmd);

        // Add default route via this WAN's gateway
        snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s table %d",
                 w->gateway, w->iface, w->table_id);

        if (run_cmd(cmd) != 0) {
            fprintf(stderr, "[SYSTEM] Warning: Failed to add route for WAN%d\n", i);
        } else {
            printf("[SYSTEM] WAN%d: Added route table %d via %s\n",
                   i, w->table_id, w->gateway);
        }

        // Disable rp_filter for WAN interface
        system_setup_rp_filter(w->iface, 0);
    }

    // Disable rp_filter for local interface
    system_setup_rp_filter(cfg->local_iface, 0);

    return 0;
}

int system_cleanup_routing_tables(lb_config_t *cfg) {
    char cmd[MAX_CMD_LEN];

    for (int i = 0; i < cfg->nwan; i++) {
        snprintf(cmd, sizeof(cmd), "ip route flush table %d 2>/dev/null",
                 cfg->wan[i].table_id);
        run_cmd(cmd);
    }

    return 0;
}

// ============== TC (Traffic Control) Operations ==============

int tc_setup_qdisc(const char *iface) {
    char cmd[MAX_CMD_LEN];

    // Remove existing qdisc first
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", iface);
    run_cmd(cmd);

    // Add clsact qdisc (allows both ingress and egress filtering)
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", iface);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "[TC] Failed to add clsact qdisc on %s\n", iface);
        return -1;
    }

    printf("[TC] Added clsact qdisc on %s\n", iface);
    return 0;
}

int tc_cleanup_qdisc(const char *iface) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", iface);
    run_cmd(cmd);
    printf("[TC] Removed qdisc from %s\n", iface);
    return 0;
}

int tc_add_redirect_filter(const char *src_iface, const char *dst_iface,
                           const char *dst_network, int prio) {
    char cmd[MAX_CMD_LEN];

    // Add filter on ingress of src_iface that redirects matching packets to dst_iface
    // Using u32 classifier to match destination network
    //
    // Format: tc filter add dev <src> ingress protocol ip prio <prio>
    //         u32 match ip dst <network> action mirred egress redirect dev <dst>

    snprintf(cmd, sizeof(cmd),
             "tc filter add dev %s ingress protocol ip prio %d "
             "u32 match ip dst %s "
             "action mirred egress redirect dev %s",
             src_iface, prio, dst_network, dst_iface);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "[TC] Failed to add redirect filter: %s -> %s\n",
                src_iface, dst_iface);
        return -1;
    }

    printf("[TC] Added filter prio %d: %s -> %s (dst: %s)\n",
           prio, src_iface, dst_iface, dst_network);
    return 0;
}

int tc_del_filter(const char *iface, int prio) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
             "tc filter del dev %s ingress prio %d 2>/dev/null", iface, prio);
    return run_cmd(cmd);
}

// Setup load balancing using TC filters with different priorities or hash
int tc_setup_load_balance(lb_config_t *cfg) {
    printf("[TC] Setting up load balancing on %s...\n", cfg->local_iface);

    pthread_mutex_lock(&cfg->tc_lock);

    // Setup clsact qdisc on local interface
    if (tc_setup_qdisc(cfg->local_iface) != 0) {
        pthread_mutex_unlock(&cfg->tc_lock);
        return -1;
    }

    // For round-robin, we'll use multiple filters with same priority
    // TC will use the first matching filter, so we need a different approach
    //
    // Option 1: Use hashlimit or flow hash
    // Option 2: Use iptables MARK + tc filter
    // Option 3: Use nexthop groups (requires newer kernel)
    //
    // We'll use flow hash for better distribution

    char cmd[MAX_CMD_LEN];

    if (cfg->lb_method == LB_HASH_FLOW || cfg->lb_method == LB_ROUND_ROBIN) {
        // Use flower classifier with action nat for nexthop selection
        // Or use multpath routing via ip route

        // Simple approach: use multipath routing
        // First, clear any existing route to remote network
        snprintf(cmd, sizeof(cmd), "ip route del %s 2>/dev/null", cfg->remote_cidr);
        run_cmd(cmd);

        // Build multipath route command
        char route_cmd[MAX_CMD_LEN * 2];
        int offset = snprintf(route_cmd, sizeof(route_cmd),
                              "ip route add %s ", cfg->remote_cidr);

        int active_count = 0;
        for (int i = 0; i < cfg->nwan; i++) {
            wan_info_t *w = &cfg->wan[i];
            if (!w->active || strlen(w->gateway) == 0) continue;

            if (active_count > 0) {
                offset += snprintf(route_cmd + offset, sizeof(route_cmd) - offset, " ");
            }

            offset += snprintf(route_cmd + offset, sizeof(route_cmd) - offset,
                               "nexthop via %s dev %s weight %d",
                               w->gateway, w->iface, w->weight);
            active_count++;
        }

        if (active_count == 0) {
            fprintf(stderr, "[TC] No active WAN interfaces for load balancing\n");
            pthread_mutex_unlock(&cfg->tc_lock);
            return -1;
        }

        if (run_cmd(route_cmd) != 0) {
            fprintf(stderr, "[TC] Failed to add multipath route\n");
            pthread_mutex_unlock(&cfg->tc_lock);
            return -1;
        }

        printf("[TC] Added multipath route with %d nexthops\n", active_count);

        // Additionally, add TC filters for marking/statistics
        for (int i = 0; i < cfg->nwan; i++) {
            wan_info_t *w = &cfg->wan[i];
            if (!w->active) continue;

            // Setup qdisc on WAN interface for statistics
            tc_setup_qdisc(w->iface);
        }
    }

    pthread_mutex_unlock(&cfg->tc_lock);
    printf("[TC] Load balancing setup complete\n");
    return 0;
}

int tc_update_load_balance(lb_config_t *cfg) {
    printf("[TC] Updating load balance configuration...\n");

    pthread_mutex_lock(&cfg->tc_lock);

    char cmd[MAX_CMD_LEN];

    // Remove old route
    snprintf(cmd, sizeof(cmd), "ip route del %s 2>/dev/null", cfg->remote_cidr);
    run_cmd(cmd);

    // Build new multipath route with only active WANs
    char route_cmd[MAX_CMD_LEN * 2];
    int offset = snprintf(route_cmd, sizeof(route_cmd),
                          "ip route add %s ", cfg->remote_cidr);

    int active_count = 0;
    for (int i = 0; i < cfg->nwan; i++) {
        wan_info_t *w = &cfg->wan[i];
        if (!w->active || strlen(w->gateway) == 0) continue;

        if (active_count > 0) {
            offset += snprintf(route_cmd + offset, sizeof(route_cmd) - offset, " ");
        }

        offset += snprintf(route_cmd + offset, sizeof(route_cmd) - offset,
                           "nexthop via %s dev %s weight %d",
                           w->gateway, w->iface, w->weight);
        active_count++;
    }

    cfg->active_wan_count = active_count;

    if (active_count > 0) {
        if (run_cmd(route_cmd) != 0) {
            fprintf(stderr, "[TC] Failed to update multipath route\n");
        } else {
            printf("[TC] Updated multipath route with %d active nexthops\n", active_count);
        }
    } else {
        fprintf(stderr, "[TC] WARNING: No active WAN interfaces!\n");
    }

    pthread_mutex_unlock(&cfg->tc_lock);
    return 0;
}

int tc_cleanup(lb_config_t *cfg) {
    char cmd[MAX_CMD_LEN];

    printf("[TC] Cleaning up...\n");

    // Remove multipath route
    snprintf(cmd, sizeof(cmd), "ip route del %s 2>/dev/null", cfg->remote_cidr);
    run_cmd(cmd);

    // Remove qdisc from local interface
    tc_cleanup_qdisc(cfg->local_iface);

    // Remove qdisc from WAN interfaces
    for (int i = 0; i < cfg->nwan; i++) {
        tc_cleanup_qdisc(cfg->wan[i].iface);
    }

    return 0;
}

int tc_get_filter_stats(const char *iface, int prio, uint64_t *packets, uint64_t *bytes) {
    char cmd[MAX_CMD_LEN];
    char output[4096];

    snprintf(cmd, sizeof(cmd), "tc -s filter show dev %s ingress prio %d 2>/dev/null",
             iface, prio);

    if (run_cmd_output(cmd, output, sizeof(output)) != 0) {
        return -1;
    }

    // Parse output for packet/byte counts
    // Format varies, look for "Sent X bytes X pkt"
    *packets = 0;
    *bytes = 0;

    char *p = strstr(output, "Sent");
    if (p) {
        sscanf(p, "Sent %lu bytes %lu pkt", bytes, packets);
    }

    return 0;
}

// ============== WAN Monitoring ==============

int wan_check_health(wan_info_t *wan) {
    if (strlen(wan->peer_ip) == 0) {
        return 0;  // No peer IP configured, assume up
    }

    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
             "ping -c 1 -W 1 -I %s %s >/dev/null 2>&1",
             wan->iface, wan->peer_ip);

    return (run_cmd(cmd) == 0) ? 0 : -1;
}

void wan_update_state(lb_config_t *cfg, int wan_idx, bool is_up) {
    wan_info_t *w = &cfg->wan[wan_idx];
    wan_state_t old_state = w->state;
    bool was_active = w->active;

    if (is_up) {
        w->fail_count = 0;
        w->success_count++;

        if (w->state != WAN_STATE_UP && w->success_count >= WAN_RECOVER_THRESHOLD) {
            w->state = WAN_STATE_UP;
            w->active = true;
        }
    } else {
        w->success_count = 0;
        w->fail_count++;

        if (w->state != WAN_STATE_DOWN && w->fail_count >= WAN_FAIL_THRESHOLD) {
            w->state = WAN_STATE_DOWN;
            w->active = false;
        }
    }

    // If state changed, update TC
    if (was_active != w->active) {
        printf("[WAN%d] State changed: %s -> %s (active: %s)\n",
               wan_idx, wan_state_str(old_state), wan_state_str(w->state),
               w->active ? "yes" : "no");

        tc_update_load_balance(cfg);
    }
}

void* wan_monitor_thread(void *arg) {
    lb_config_t *cfg = (lb_config_t *)arg;

    printf("[WAN Monitor] Thread started\n");

    // Initial check
    for (int i = 0; i < cfg->nwan; i++) {
        cfg->wan[i].state = WAN_STATE_CHECKING;
    }

    while (cfg->running) {
        for (int i = 0; i < cfg->nwan; i++) {
            wan_info_t *w = &cfg->wan[i];

            int result = wan_check_health(w);

            pthread_mutex_lock(&cfg->lock);
            wan_update_state(cfg, i, result == 0);
            pthread_mutex_unlock(&cfg->lock);
        }

        usleep(WAN_CHECK_INTERVAL_MS * 1000);
    }

    printf("[WAN Monitor] Thread stopped\n");
    return NULL;
}

// ============== Statistics Collector ==============

void stats_print(const lb_config_t *cfg, const lb_stats_t *stats) {
    printf("\r[STATS] Active WANs: %d/%d | ", cfg->active_wan_count, cfg->nwan);

    for (int i = 0; i < cfg->nwan; i++) {
        const wan_info_t *w = &cfg->wan[i];
        printf("%s:%s ", w->iface, wan_state_str(w->state));
    }

    printf("| TX: %lu pkts", stats->total_packets);
    fflush(stdout);
}

void* stats_collector_thread(void *arg) {
    lb_config_t *cfg = (lb_config_t *)arg;
    lb_stats_t stats = {0};

    printf("[Stats] Collector thread started\n");

    while (cfg->running) {
        // Read interface statistics
        for (int i = 0; i < cfg->nwan; i++) {
            wan_info_t *w = &cfg->wan[i];

            char path[256];
            char buf[64];
            FILE *f;

            // Read TX packets
            snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", w->iface);
            f = fopen(path, "r");
            if (f) {
                if (fgets(buf, sizeof(buf), f)) {
                    uint64_t new_val = strtoull(buf, NULL, 10);
                    if (w->packets_tx > 0) {
                        stats.packets_per_wan[i] = new_val - w->packets_tx;
                    }
                    w->packets_tx = new_val;
                }
                fclose(f);
            }

            // Read TX bytes
            snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", w->iface);
            f = fopen(path, "r");
            if (f) {
                if (fgets(buf, sizeof(buf), f)) {
                    uint64_t new_val = strtoull(buf, NULL, 10);
                    if (w->bytes_tx > 0) {
                        stats.bytes_per_wan[i] = new_val - w->bytes_tx;
                    }
                    w->bytes_tx = new_val;
                }
                fclose(f);
            }
        }

        // Calculate totals
        stats.total_packets = 0;
        stats.total_bytes = 0;
        for (int i = 0; i < cfg->nwan; i++) {
            stats.total_packets += stats.packets_per_wan[i];
            stats.total_bytes += stats.bytes_per_wan[i];
        }

        pthread_mutex_lock(&cfg->lock);
        stats_print(cfg, &stats);
        pthread_mutex_unlock(&cfg->lock);

        usleep(STATS_INTERVAL_MS * 1000);
    }

    printf("\n[Stats] Collector thread stopped\n");
    return NULL;
}
