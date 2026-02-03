#ifndef SYSTEM_H
#define SYSTEM_H

/* ---- IPv4 forwarding ---- */

int system_get_ip_forward(void);
int system_enable_ip_forward(void);
int system_disable_ip_forward(void);

/* ---- Routing ---- */

int system_add_route_dev(const char *cidr, const char *ifname);
int system_del_route_dev(const char *cidr, const char *ifname);

/* ---- Network device ---- */

int netdev_create_veth_pair(const char *if_in, const char *if_out, int mtu);
int netdev_delete(const char *ifname);
int netdev_set_up(const char *ifname);
int system_get_if_hwaddr(const char *ifname, unsigned char mac[6]);

/*
 * Disable GRO/GSO/TSO offloads on interface.
 * Required for AF_PACKET raw datapath — prevents kernel from
 * aggregating TCP segments into super-packets (64KB) that exceed
 * WAN MTU (1500) and cause sendto() EMSGSIZE errors.
 */
int netdev_disable_offloads(const char *ifname);

#endif /* SYSTEM_H */

