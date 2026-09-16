#include "mwan_lb_mode.h"

/* Change only MWAN_LB_MODE, then rebuild the module, to select the datapath
 * used by this experimental branch.  Keep this decision in one C file so
 * different translation units cannot accidentally be built in mixed modes. */
#define MWAN_LB_PER_FLOW    0
#define MWAN_LB_PER_PACKET  1

#define MWAN_LB_MODE MWAN_LB_PER_PACKET

#if MWAN_LB_MODE != MWAN_LB_PER_FLOW && \
    MWAN_LB_MODE != MWAN_LB_PER_PACKET
#error "MWAN_LB_MODE must be MWAN_LB_PER_FLOW or MWAN_LB_PER_PACKET"
#endif

bool mwan_lb_per_packet_enabled(void)
{
    return MWAN_LB_MODE == MWAN_LB_PER_PACKET;
}

const char *mwan_lb_mode_name(void)
{
    return mwan_lb_per_packet_enabled() ? "per-packet" : "per-flow";
}
