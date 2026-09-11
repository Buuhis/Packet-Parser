#ifndef MWAN_MAC_DISCOVERY_H
#define MWAN_MAC_DISCOVERY_H

#include <linux/types.h>

struct mwan_tunnel;
struct mwan_config;

int mwan_mac_discovery_init(void);
void mwan_mac_discovery_cleanup(void);
void mwan_mac_discovery_kick(void);
int mwan_mac_discovery_configure_pending(u32 node_id, u32 generation,
                                         const u32 *ifindices,
                                         u32 num_tunnels);
void mwan_mac_discovery_import_pending(struct mwan_config *cfg);
void mwan_mac_discovery_clear_pending(u32 node_id);
int mwan_mac_discovery_get_pending_peer(u32 ifindex,
                                        __be32 *peer_tunnel_ip);
int mwan_mac_discovery_set_pending_state(u32 ifindex, u32 generation,
                                         u32 sequence, bool up);
int mwan_mac_discovery_get_pending_state(u32 ifindex, u32 *generation,
                                         u32 *sequence, bool *up);
int mwan_mac_discovery_rebind_pending(u32 node_id, u32 generation,
                                      u32 old_ifindex, u32 new_ifindex);
bool mwan_mac_get_peer(struct mwan_tunnel *tun, u8 mac[6]);
bool mwan_mac_get_peer_tunnel_ip(struct mwan_tunnel *tun,
                                 __be32 *peer_tunnel_ip);

#endif /* MWAN_MAC_DISCOVERY_H */
