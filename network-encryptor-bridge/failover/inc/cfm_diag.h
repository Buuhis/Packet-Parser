#ifndef CFM_DIAG_H
#define CFM_DIAG_H

#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>

struct app_config;
struct forwarder;

typedef enum {
    CFM_LINK_STATE_INIT = 0,
    CFM_LINK_STATE_UP = 1,
    CFM_LINK_STATE_DOWN = -1
} cfm_link_state_t;

typedef struct y1731_metrics {
    uint32_t rtt_us;        // Round-trip time in microseconds
    uint32_t jitter_us;     // Jitter in microseconds
    float    loss_rate;     // Frame loss rate (0.0 to 1.0)
    int      loss_mechanism;// 1 = LMM, 2 = SLM
} y1731_metrics_t;

/* A point-in-time view of one WAN interface monitored by CFM. */
typedef struct cfm_link_status {
    char ifname[IF_NAMESIZE];
    int wan_dp;
    cfm_link_state_t state;
    bool quality_is_bad;
} cfm_link_status_t;

/**
 * Initialize the CFM diagnostic subsystem.
 * This reads WAN ports from the configuration, opens Raw sockets, 
 * and spawns the background monitoring threads.
 *
 * @param cfg Pointer to the loaded app_config containing WAN interfaces.
 * @return 0 on success, negative error code on failure.
 */
int cfm_init(const struct app_config *cfg);

/**
 * Query the health status of a WAN interface by dataplane index.
 *
 * @param wan_dp The dataplane index of the WAN interface.
 * @return true if the link is active and CCM packets are being received,
 *         false if the link has timed out (failed) or is not initialized.
 */
bool cfm_is_link_up(int wan_dp);

/**
 * Query the detailed state of a WAN interface by dataplane index.
 *
 * @param wan_dp The dataplane index of the WAN interface.
 * @return 0 for INIT, 1 for UP, 2 for DOWN.
 */
int cfm_get_link_state(int wan_dp);

/**
 * Query the quality metrics of a WAN interface by dataplane index.
 *
 * @param wan_dp The dataplane index of the WAN interface.
 * @param metrics Pointer to struct where quality metrics will be stored.
 * @return 0 on success, negative error code on failure.
 */
int cfm_get_link_quality(int wan_dp, y1731_metrics_t *metrics);

/**
 * Copy the current status of all WAN interfaces actively monitored by CFM.
 * The returned state is the raw CFM state; quality_is_bad must also be
 * considered because failover treats a bad-quality link as unavailable.
 *
 * @return Number of copied entries, or negative on invalid arguments.
 */
int cfm_get_monitored_link_status(cfm_link_status_t *statuses, int max_statuses);

/* CLI handler for `network-encryptor -gs <interface>`. */
int cfm_handle_get_status(const char *ifname);

/**
 * Terminate the CFM diagnostic subsystem.
 * This stops background threads, cleans up resources, and closes Raw sockets.
 */
void cfm_cleanup(void);

/**
 * Update latency/loss thresholds dynamically when config reloads.
 */
void cfm_update_thresholds(const struct app_config *cfg);

#endif // CFM_DIAG_H
