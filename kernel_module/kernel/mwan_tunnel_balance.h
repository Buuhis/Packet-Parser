#ifndef MWAN_TUNNEL_BALANCE_H
#define MWAN_TUNNEL_BALANCE_H

#include <linux/types.h>

struct mwan_config;

void mwan_tunnel_balance_init(struct mwan_config *cfg);
int mwan_tunnel_balance_assign_flow(struct mwan_config *cfg, u32 flow_hash);
int mwan_tunnel_balance_assign_exact(struct mwan_config *cfg, u16 tunnel_idx);
int mwan_tunnel_balance_reassign_flow(struct mwan_config *cfg,
                                      u16 old_tunnel_idx, u32 flow_hash);
void mwan_tunnel_balance_release_flow(struct mwan_config *cfg,
                                      u16 tunnel_idx);
void mwan_tunnel_balance_account_bytes(struct mwan_config *cfg,
                                       u16 tunnel_idx, u32 bytes);
bool mwan_tunnel_balance_is_active(const struct mwan_config *cfg,
                                   u16 tunnel_idx);

#endif /* MWAN_TUNNEL_BALANCE_H */
