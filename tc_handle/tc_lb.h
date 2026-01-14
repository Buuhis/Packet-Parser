#ifndef TC_LB_H
#define TC_LB_H

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <netinet/in.h>

// ============== Configuration ==============
#define MAX_WAN 10
#define MAX_IFACE_NAME 32
#define MAX_CMD_LEN 512
#define MAX_IP_LEN 64

#define WAN_CHECK_INTERVAL_MS 1000      // Check WAN status every 1s
#define STATS_INTERVAL_MS 1000          // Collect stats every 1s
#define WAN_PING_TIMEOUT_MS 500         // Ping timeout
#define WAN_FAIL_THRESHOLD 3            // Mark WAN down after 3 failed pings
#define WAN_RECOVER_THRESHOLD 2         // Mark WAN up after 2 successful pings

// TC priorities for filters
#define TC_PRIO_BASE 10

// ============== Load Balance Methods ==============
typedef enum {
    LB_ROUND_ROBIN = 0,
    LB_HASH_FLOW,           // Hash by src_ip + dst_ip + src_port + dst_port
    LB_WEIGHTED_RR,         // Weighted round robin
} lb_method_t;

// ============== WAN State ==============
typedef enum {
    WAN_STATE_UNKNOWN = 0,
    WAN_STATE_UP,
    WAN_STATE_DOWN,
    WAN_STATE_CHECKING,
} wan_state_t;

// ============== WAN Interface ==============
typedef struct {
    char iface[MAX_IFACE_NAME];         // Interface name (e.g., eth1)
    char gateway[MAX_IP_LEN];           // Gateway IP for this WAN
    char peer_ip[MAX_IP_LEN];           // Peer IP to ping for health check
    int weight;                         // Weight for weighted round robin
    int table_id;                       // Routing table ID for this WAN

    // Runtime state
    wan_state_t state;
    int fail_count;                     // Consecutive ping failures
    int success_count;                  // Consecutive ping successes
    bool active;                        // Currently participating in LB

    // Statistics
    uint64_t packets_tx;
    uint64_t bytes_tx;
    uint64_t packets_dropped;
} wan_info_t;

// ============== Global Configuration ==============
typedef struct {
    // Local interface
    char local_iface[MAX_IFACE_NAME];

    // Remote network to load balance
    uint32_t remote_network;            // Network address
    uint32_t remote_mask;               // Network mask
    int remote_prefix;                  // Prefix length (e.g., 24)
    char remote_cidr[MAX_IP_LEN];       // CIDR string (e.g., "192.168.2.0/24")

    // WAN interfaces
    wan_info_t wan[MAX_WAN];
    int nwan;
    int active_wan_count;               // Number of currently active WANs

    // Load balancing
    lb_method_t lb_method;
    int rr_index;                       // Current round-robin index

    // Thread control
    volatile bool running;
    pthread_mutex_t lock;               // Global lock for shared state
    pthread_mutex_t tc_lock;            // Lock for TC operations
} lb_config_t;

// ============== Statistics ==============
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t packets_per_wan[MAX_WAN];
    uint64_t bytes_per_wan[MAX_WAN];
    uint64_t tc_redirects;
    uint64_t tc_drops;
} lb_stats_t;

// ============== Function Declarations ==============

// Configuration
int config_load(lb_config_t *cfg, const char *path);
void config_print(const lb_config_t *cfg);
int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask, int *prefix);

// System setup
int system_setup_ip_forwarding(bool enable);
int system_setup_rp_filter(const char *iface, int value);
int system_setup_routing_tables(lb_config_t *cfg);
int system_cleanup_routing_tables(lb_config_t *cfg);

// TC (Traffic Control) operations
int tc_setup_qdisc(const char *iface);
int tc_cleanup_qdisc(const char *iface);
int tc_add_redirect_filter(const char *src_iface, const char *dst_iface,
                           const char *dst_network, int prio);
int tc_del_filter(const char *iface, int prio);
int tc_setup_load_balance(lb_config_t *cfg);
int tc_update_load_balance(lb_config_t *cfg);
int tc_cleanup(lb_config_t *cfg);
int tc_get_filter_stats(const char *iface, int prio, uint64_t *packets, uint64_t *bytes);

// WAN monitoring
void* wan_monitor_thread(void *arg);
int wan_check_health(wan_info_t *wan);
void wan_update_state(lb_config_t *cfg, int wan_idx, bool is_up);

// Statistics
void* stats_collector_thread(void *arg);
void stats_print(const lb_config_t *cfg, const lb_stats_t *stats);

// Utility
int run_cmd(const char *cmd);
int run_cmd_output(const char *cmd, char *output, size_t output_size);
uint64_t get_time_ms(void);
const char* wan_state_str(wan_state_t state);
const char* lb_method_str(lb_method_t method);

#endif // TC_LB_H
