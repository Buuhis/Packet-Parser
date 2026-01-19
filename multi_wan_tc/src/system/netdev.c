#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "system.h"
#include "../utils/logger.h"

/*
 * Create veth pair:
 *   if_in  : kernel side (TC will redirect into this)
 *   if_out : userspace side (AF_PACKET will read from this)
 */
int netdev_create_veth_pair(const char *if_in, const char *if_out, int mtu)
{
    char cmd[256];

    // delete if exists (idempotent)
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", if_in);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }

    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s",
             if_in, if_out);

    if (system(cmd) != 0) {
        log_error("Failed to create veth pair %s <-> %s", if_in, if_out);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s mtu %d", if_in, mtu);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }
    snprintf(cmd, sizeof(cmd), "ip link set %s mtu %d", if_out, mtu);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s up", if_in);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }
    snprintf(cmd, sizeof(cmd), "ip link set %s up", if_out);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }

    log_info("Created veth pair: %s <-> %s (mtu=%d)",
             if_in, if_out, mtu);

    return 0;
}

int netdev_delete(const char *ifname)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", ifname);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }
    return 0;
}

int netdev_set_up(const char *ifname)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
    return system(cmd);
}

