#ifndef SDWAN_FAILOVER_POLICY_H
#define SDWAN_FAILOVER_POLICY_H

#include <stdint.h>

enum failover_snapshot_action {
    FAILOVER_SNAPSHOT_REUSE = 0,
    FAILOVER_SNAPSHOT_WAIT,
    FAILOVER_SNAPSHOT_REBIND,
};

/* Device identity and config version are independent signals.  Only an
 * ifindex change proves that the live BFD session is attached to an obsolete
 * device.  Query failures and generation mismatches must preserve the
 * session until a coherent snapshot is available. */
enum failover_snapshot_action failover_snapshot_action(
    unsigned int runtime_ifindex, unsigned int current_ifindex,
    int query_error, uint32_t expected_generation,
    uint32_t observed_generation);

#endif /* SDWAN_FAILOVER_POLICY_H */
