#include "tc/tc.h"
#include "utils/logger.h"

#include <stdio.h>
#include <stdlib.h>

static int run(const char *cmd)
{
    log_info("EXEC: %s", cmd);
    return system(cmd);
}

/* RX-1: redirect ingress on WAN to veth_rx_in, then drop to avoid duplicate */
int tc_rx_wan_ingress_to_veth(const char *wan_if, const char *veth_rx_in)
{
    char cmd[512];

    /* clsact on WAN */
    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s clsact", wan_if);
    if (run(cmd) != 0) return -1;

    /* delete old ingress filters */
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress 2>/dev/null", wan_if);
    system(cmd);

    /* redirect to veth_rx_in and drop */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 10 flower "
        "action mirred egress redirect dev %s "
        "action drop",
        wan_if, veth_rx_in);

    return run(cmd);
}

int tc_rx_cleanup(const char *wan_if)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress 2>/dev/null", wan_if);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", wan_if);
    system(cmd);

    return 0;
}
