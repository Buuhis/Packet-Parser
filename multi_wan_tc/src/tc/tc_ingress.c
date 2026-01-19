#include <stdio.h>
#include <stdlib.h>

#include "tc.h"
#include "../utils/logger.h"

/*
 * Attach clsact + ingress redirect
 *   src_if : local_if (eth0)
 *   dst_if : veth_tx_in
 */
int tc_ingress_redirect(const char *src_if, const char *dst_if)
{
    char cmd[512];

    // clsact (ignore error if exists)
    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s clsact 2>/dev/null",
             src_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }

    // ingress redirect all IPv4
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip "
        "prio 10 "
        "flower "
        "action mirred ingress redirect dev %s",
        src_if, dst_if);

    if (system(cmd) != 0) {
        log_error("Failed to add TC ingress redirect %s -> %s",
                  src_if, dst_if);
        return -1;
    }

    log_info("TC ingress redirect: %s -> %s", src_if, dst_if);
    return 0;
}

int tc_ingress_cleanup(const char *src_if)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null",
             src_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }
    log_info("TC ingress cleaned on %s", src_if);
    return 0;
}

