#include "mwan_lb_mode.h"

#include <linux/atomic.h>
#include <linux/errno.h>

/* Runtime mode is intentionally independent from mwan_config and PQC key
 * state. Full config apply, BFD and PQC control traffic must not reset it. */
static atomic_t mwan_lb_mode = ATOMIC_INIT(MWAN_LB_PER_FLOW);

u8 mwan_lb_mode_get(void)
{
    return (u8)atomic_read(&mwan_lb_mode);
}

int mwan_lb_mode_set(u8 mode)
{
    if (mode != MWAN_LB_PER_FLOW && mode != MWAN_LB_PER_PACKET)
        return -EINVAL;
    atomic_set(&mwan_lb_mode, mode);
    return 0;
}

bool mwan_lb_per_packet_enabled(void)
{
    return mwan_lb_mode_get() == MWAN_LB_PER_PACKET;
}

const char *mwan_lb_mode_value_name(u8 mode)
{
    return mode == MWAN_LB_PER_PACKET ? "per-packet" : "per-flow";
}

const char *mwan_lb_mode_name(void)
{
    return mwan_lb_mode_value_name(mwan_lb_mode_get());
}
