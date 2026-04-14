#ifndef MWAN_STATE_H
#define MWAN_STATE_H

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <crypto/aead.h>
#include "mwan_proto.h"

#define MAX_MWAN_TUNNELS 8
#define MWAN_LUT_SIZE    256

enum mwan_encap_type {
    MWAN_ENCAP_NONE = 0,
    MWAN_ENCAP_MACSEC,
    MWAN_ENCAP_L3_CUSTOM,
};

struct mwan_tunnel;

struct mwan_tunnel {
    u32 ifindex;
    u32 weight;
    __be32 gateway;

    /* Caching fields for performance */
    struct net_device *dev;
    unsigned char gateway_mac[6];
    bool mac_resolved;
    bool is_ethernet;
    enum mwan_encap_type encap_type;
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

    /* Encryption (AES-GCM) */
    bool encrypt_on;
    u8   encrypt_type;                    /* enum mwan_crypt_type */
    u8   encrypt_key[MWAN_MAX_KEY_LEN];
    u8   encrypt_key_len;                 /* 16 (128-bit) or 32 (256-bit) */
    u8   encrypt_salt[MWAN_SALT_LEN];
    struct crypto_aead *tfm;              /* Crypto transform context */
    atomic64_t encrypt_seq;               /* Auto-increment sequence for IV */
    
    struct rcu_head rcu;
};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);

#endif /* MWAN_STATE_H */
