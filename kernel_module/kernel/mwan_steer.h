#ifndef MWAN_STEER_H
#define MWAN_STEER_H

#include <linux/skbuff.h>
#include "mwan_state.h"

#define MWAN_DECAP_CONTINUE  (-1)

struct mwan_tx_flow_context;

int mwan_steer_init(void);
void mwan_steer_cleanup(void);

unsigned int mwan_handle_encap_none(struct sk_buff *skb,
                                    struct mwan_config *cfg, u16 tunnel_idx,
                                    const struct mwan_tx_flow_context *tx_ctx);
unsigned int mwan_handle_encap_none_direct(struct sk_buff *skb,
                                           struct mwan_tunnel *tun);
int mwan_encap_none_xmit(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_macsec(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_l3(struct sk_buff *skb, struct mwan_tunnel *tun);

int mwan_handle_decap_l3(struct sk_buff *skb, struct mwan_config *cfg);
unsigned int mwan_handle_encap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_decap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun);
unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb,
                                      struct mwan_config *cfg,
                                      u16 tunnel_idx,
                                      const struct mwan_tx_flow_context *tx_ctx);
int mwan_l2_pqc_encrypt_xmit(struct sk_buff *skb,
                             struct mwan_l2_worker *worker,
                             struct mwan_tunnel *tun, u64 flow_token,
                             u32 seq);
int mwan_decap_l2_pqc_init(void);
void mwan_decap_l2_pqc_cleanup(void);

#endif /* MWAN_STEER_H */
