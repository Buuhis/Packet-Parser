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

    /* Delete existing clsact first (cleanup from previous run) */
    // snprintf(cmd, sizeof(cmd),
    //          "tc qdisc del dev %s clsact 2>/dev/null",
    //          src_if);
    // if (system(cmd) != 0) {
    //     log_error("Failed to delete clsact qdisc on %s", src_if);
    //     return -1;
    // }

    /* Add clsact qdisc */
    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s clsact",
             src_if);
    if (system(cmd) != 0) {
        log_error("Failed to add clsact qdisc on %s", src_if);
        return -1;
    }

    /* ingress redirect all IPv4 */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 10 flower "
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

int tc_ingress_drop_cidr(const char *ifname, const char *dst_cidr)
{
    char cmd[512];

    /* Delete existing clsact first */
    // snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    // if (system(cmd) != 0) {
    //     log_error("Failed to delete clsact qdisc on %s", ifname);
    //     return -1;
    // }

    /* Add clsact qdisc */
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
    if (system(cmd) != 0) {
        log_error("Failed to add clsact on %s", ifname);
        return -1;
    }

    /* Drop packets going to remote CIDR so kernel doesn't process them */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 1 flower dst_ip %s "
        "action drop",
        ifname, dst_cidr);

    if (system(cmd) != 0) {
        log_error("Failed to add TC ingress drop for %s on %s", dst_cidr, ifname);
        return -1;
    }

    log_info("TC ingress drop: %s (dst) on %s", dst_cidr, ifname);
    return 0;
}

int tc_ingress_cleanup(const char *src_if)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null",
             src_if);
    if (system(cmd) != 0) {
        log_debug("TC cleanup: %s (might not exist)", cmd);
    } else {
        log_info("TC ingress cleaned up successfully on %s", src_if);
    }
    return 0;
}

