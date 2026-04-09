#ifndef MWAN_STEER_H
#define MWAN_STEER_H

#include <linux/skbuff.h>
#include "mwan_state.h"

int mwan_steer_init(void);
void mwan_steer_cleanup(void);

unsigned int mwan_handle_encap_none(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_macsec(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_l3(struct sk_buff *skb, struct mwan_tunnel *tun);

#endif /* MWAN_STEER_H */
