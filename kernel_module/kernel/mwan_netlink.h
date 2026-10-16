#ifndef MWAN_NETLINK_H
#define MWAN_NETLINK_H

#include <linux/types.h>

int mwan_netlink_init(void);
void mwan_netlink_cleanup(void);
int mwan_netlink_notify_peer_changed(u32 ifindex, __be32 peer_tunnel_ip,
                                     u32 peer_generation);

#endif /* MWAN_NETLINK_H */
