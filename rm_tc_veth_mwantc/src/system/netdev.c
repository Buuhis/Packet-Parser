#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>

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

int netdev_disable_offloads(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ethtool -K %s gro off gso off tso off 2>/dev/null",
             ifname);

    int ret = system(cmd);
    if (ret != 0) {
        log_error("Failed to disable offloads on %s (ethtool not available?)",
                  ifname);
        return -1;
    }

    log_info("Disabled GRO/GSO/TSO on %s", ifname);
    return 0;
}

int system_get_if_hwaddr(const char *ifname, unsigned char mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("socket(AF_INET) failed: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        log_error("ioctl(SIOCGIFHWADDR, %s) failed: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}
