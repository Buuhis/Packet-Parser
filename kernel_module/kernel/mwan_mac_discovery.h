#ifndef MWAN_MAC_DISCOVERY_H
#define MWAN_MAC_DISCOVERY_H

#include <linux/types.h>

struct mwan_tunnel;

int mwan_mac_discovery_init(void);
void mwan_mac_discovery_cleanup(void);
void mwan_mac_discovery_kick(void);
bool mwan_mac_get_peer(struct mwan_tunnel *tun, u8 mac[6]);
bool mwan_mac_get_peer_tunnel_ip(struct mwan_tunnel *tun,
                                 __be32 *peer_tunnel_ip);

#endif /* MWAN_MAC_DISCOVERY_H */
