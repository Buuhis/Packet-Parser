#ifndef CFM_DIAG_H
#define CFM_DIAG_H

#include <stdbool.h>

struct app_config;
struct forwarder;

typedef enum {
    CFM_LINK_STATE_INIT = 0,
    CFM_LINK_STATE_UP = 1,
    CFM_LINK_STATE_DOWN = -1
} cfm_link_state_t;

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
 * Terminate the CFM diagnostic subsystem.
 * This stops background threads, cleans up resources, and closes Raw sockets.
 */
void cfm_cleanup(void);

#endif // CFM_DIAG_H
