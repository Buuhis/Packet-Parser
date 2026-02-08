#include <stdio.h>
#include <stdlib.h>

#include "tc.h"
#include "../utils/logger.h"

/*
 * Attach clsact + ingress redirect on WAN interface
 * Filter: ip src <remote_cidr> -> redirect to dst_if (veth_rx_out)
 *
 *   wan_if     : WAN interface (enp4s0, enp5s0, ...)
 *   dst_if     : veth_rx_out (userspace side)
 *   src_cidr   : remote CIDR to filter (192.168.182.0/24)
 */
int tc_wan_ingress_redirect_cidr(const char *wan_if,
                                  const char *dst_if,
                                  const char *src_cidr)
{
    char cmd[512];

    /* Delete existing clsact first (cleanup from previous run) */
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null",
             wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to delete qdisc on WAN %s", wan_if);
        return -1;
    }

    /* Add clsact qdisc */
    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s clsact",
             wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to add clsact qdisc on WAN %s", wan_if);
        return -1;
    }

    /* ingress redirect: filter ip src <src_cidr> */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 10 flower "
        "action mirred ingress redirect dev %s",
        wan_if, dst_if);

    if (system(cmd) != 0) {
        log_error("Failed to add TC WAN ingress redirect %s -> %s",
                  wan_if, dst_if);
        return -1;
    }

    log_info("TC WAN ingress redirect: %s -> %s",
             wan_if, dst_if);
    return 0;
}

/*
 * Simple version: redirect ALL IPv4 traffic
 */
int tc_wan_ingress_redirect(const char *wan_if, const char *dst_if)
{
    char cmd[512];

    /* Delete existing clsact first (cleanup from previous run) */
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null",
             wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to delete qdisc dev %s clsact", wan_if);
        return -1;
    }

    /* Add clsact qdisc */
    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s clsact",
             wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to add clsact qdisc on WAN %s", wan_if);
        return -1;
    }

    /* ingress redirect all IPv4 */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 10 flower "
        "action mirred ingress redirect dev %s",
        wan_if, dst_if);

    if (system(cmd) != 0) {
        log_error("Failed to add TC WAN ingress redirect %s -> %s",
                  wan_if, dst_if);
        return -1;
    }

    log_info("TC WAN ingress redirect: %s -> %s", wan_if, dst_if);
    return 0;
}

int tc_wan_ingress_drop_cidr(const char *wan_if, const char *src_cidr)
{
    char cmd[512];

    /* Delete existing clsact first */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to delete qdisc dev %s clsact", wan_if);
        return -1;
    }

    /* Add clsact qdisc */
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to add clsact on WAN %s", wan_if);
        return -1;
    }

    /* Drop packets coming from remote CIDR */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 1 flower src_ip %s "
        "action drop",
        wan_if, src_cidr);

    if (system(cmd) != 0) {
        log_error("Failed to add TC WAN ingress drop for %s on %s", src_cidr, wan_if);
        return -1;
    }

    log_info("TC WAN ingress drop: %s (src) on %s", src_cidr, wan_if);
    return 0;
}

int tc_wan_ingress_cleanup(const char *wan_if)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null",
             wan_if);
    if (system(cmd) != 0) {
        log_error("Failed to delete qdisc clsact on WAN %s", wan_if);
        return -1;
    }
    log_info("TC WAN ingress cleaned on %s", wan_if);
    return 0;
}
