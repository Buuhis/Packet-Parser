#ifndef MWAN_MAC_DISCOVERY_H
#define MWAN_MAC_DISCOVERY_H

#include <linux/types.h>

struct mwan_tunnel;

int mwan_mac_discovery_init(void);
void mwan_mac_discovery_cleanup(void);
void mwan_mac_discovery_kick(void);
bool mwan_mac_get_peer(struct mwan_tunnel *tun, u8 mac[6]);

#endif /* MWAN_MAC_DISCOVERY_H */
