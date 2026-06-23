#ifndef CFM_DIAG_H
#define CFM_DIAG_H

#include <stdbool.h>

struct app_config;
struct forwarder;

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
 * Query the health status of a WAN interface by index.
 *
 * @param wan_idx The index of the WAN interface in the cfg->wans array.
 * @return true if the link is active and CCM packets are being received,
 *         false if the link has timed out (failed) or is not initialized.
 */
bool cfm_is_link_up(int wan_idx);

/**
 * Perform WAN failover lookup: if the initially chosen WAN is down,
 * returns an alternative active WAN from the same profile, or falls back.
 */
int failover_select_wan(const struct app_config *cfg, int profile_idx, int initial_wan_idx);

/**
 * Perform WAN failover lookup on dataplane index.
 */
int failover_select_wan_dp(const struct forwarder *fwd, int profile_idx, int initial_dp);

/**
 * Terminate the CFM diagnostic subsystem.
 * This stops background threads, cleans up resources, and closes Raw sockets.
 */
void cfm_cleanup(void);

#endif // CFM_DIAG_H
