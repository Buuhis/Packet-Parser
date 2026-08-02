#ifndef MWAN_STATE_H
#define MWAN_STATE_H

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <crypto/aead.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include "mwan_proto.h"

#define MWAN_REORDER_TIMEOUT msecs_to_jiffies(30)
#define MWAN_REORDER_RING_SIZE 1024
#define MWAN_REORDER_RING_MASK (MWAN_REORDER_RING_SIZE - 1)
#define MAX_MWAN_TUNNELS 100
#define MWAN_LUT_SIZE    256
#define MWAN_FLOW_TABLE_SIZE 256
#define MWAN_FLOW_RING_SIZE  256
#define MWAN_FLOW_RING_MASK  (MWAN_FLOW_RING_SIZE - 1)

enum mwan_encap_type {
    MWAN_ENCAP_NONE = 0,
    MWAN_ENCAP_MACSEC,
    MWAN_ENCAP_L3_CUSTOM,
    MWAN_ENCAP_L3_PQC,      /* L3 AES-GCM with PQC-derived session key */
    MWAN_ENCAP_L2_PQC,      /* L2 AES-GCM with PQC-derived session key */
};

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

struct mwan_per_flow_reorder {
    struct sk_buff *ring[MWAN_FLOW_RING_SIZE];
    atomic64_t expected_seq;
    spinlock_t drain_lock;
    unsigned long slot_time[MWAN_FLOW_RING_SIZE];
};

struct mwan_reorder_ring {
    struct sk_buff *ring[MWAN_REORDER_RING_SIZE];
    atomic64_t expected_seq;
    spinlock_t drain_lock;
    struct timer_list timer;
    unsigned long slot_time[MWAN_REORDER_RING_SIZE];
};

struct mwan_config {
    u32 node_id;
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
    u8   encrypt_layer;                   /* 2=L2 (MACsec), 3=L3 (Overlay) */
    u8   encrypt_type;                    /* enum mwan_crypt_type */
    u8   encrypt_key[MWAN_MAX_KEY_LEN];
    u8   encrypt_key_len;                 /* 16 (128-bit) or 32 (256-bit) */
    u8   encrypt_salt[MWAN_SALT_LEN];
    struct crypto_aead *tfm;              /* Crypto transform context */
    atomic64_t encrypt_seq;               /* Auto-increment sequence for IV */
    
    atomic64_t flow_tx_seq[MWAN_FLOW_TABLE_SIZE];
    struct mwan_per_flow_reorder flow_reorder[MWAN_FLOW_TABLE_SIZE];

    struct timer_list reorder_timer;
    int num_workers;
    int worker_start_cpu;

    struct rcu_head rcu;
};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);
void mwan_reorder_timeout(struct timer_list *t);

#endif /* MWAN_STATE_H */
