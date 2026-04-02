#ifndef MWAN_STATE_H
#define MWAN_STATE_H

#include <linux/types.h>
#include <linux/rcupdate.h>

#define MAX_MWAN_TUNNELS 8
#define MWAN_LUT_SIZE    256

struct mwan_tunnel {
    u32 ifindex;
    u32 weight;
    __be32 gateway;

    /* Caching fields for performance */
    struct net_device *dev;
    unsigned char gateway_mac[6];
    bool mac_resolved;
    bool is_ethernet;
};

struct mwan_config {
    u32 node_id;
    __be32 cidr_ip;
    __be32 cidr_mask;
    u32 num_tunnels;
    u32 total_weight; /* Pre-calculated total weight */
    
    /* Lookup table for O(1) weight-proportional tunnel selection */
    u8  tunnel_idx_lut[MWAN_LUT_SIZE];
    
    struct mwan_tunnel tunnels[MAX_MWAN_TUNNELS];

    /* Local network for Inbound Steering */
    __be32 local_ip;
    __be32 local_mask;
    u32 local_ifindex;
    struct net_device *local_dev;
    
    struct rcu_head rcu;
};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);

#endif /* MWAN_STATE_H */
