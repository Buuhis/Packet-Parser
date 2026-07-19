#ifndef MWAN_STEER_H
#define MWAN_STEER_H

#include <linux/skbuff.h>
#include "mwan_state.h"

#define MWAN_DECAP_CONTINUE  (-1)

int mwan_steer_init(void);
void mwan_steer_cleanup(void);

unsigned int mwan_handle_encap_none(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_macsec(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_l3(struct sk_buff *skb, struct mwan_tunnel *tun);

int mwan_handle_decap_l3(struct sk_buff *skb, struct mwan_config *cfg);
unsigned int mwan_handle_encap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_decap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun);
bool mwan_resolve_gateway_mac(struct mwan_tunnel *tun, struct net_device *dev, u8 *mac_out);

#endif /* MWAN_STEER_H */
