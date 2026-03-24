#ifndef MWAN_STATE_H
#define MWAN_STATE_H

#include <linux/types.h>
#include <linux/rcupdate.h>

#define MAX_MWAN_TUNNELS 8

struct mwan_tunnel {
    u32 ifindex;
    u32 weight;
    __be32 gateway;
};

struct mwan_config {
    u32 node_id;
    __be32 cidr_ip;
    __be32 cidr_mask;
    u32 num_tunnels;
    struct mwan_tunnel tunnels[MAX_MWAN_TUNNELS];
    
    struct rcu_head rcu;
};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);

#endif /* MWAN_STATE_H */
