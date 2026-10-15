#include "failover_policy.h"

enum failover_snapshot_action failover_snapshot_action(
    unsigned int runtime_ifindex, unsigned int current_ifindex,
    int query_error, uint32_t expected_generation,
    uint32_t observed_generation)
{
    if (runtime_ifindex != current_ifindex)
        return FAILOVER_SNAPSHOT_REBIND;
    if (query_error != 0 || observed_generation != expected_generation)
        return FAILOVER_SNAPSHOT_WAIT;
    return FAILOVER_SNAPSHOT_REUSE;
}
