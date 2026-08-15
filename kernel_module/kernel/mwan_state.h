#ifndef MWAN_STATE_H
#define MWAN_STATE_H

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include "mwan_proto.h"

#define MWAN_REORDER_TIMEOUT msecs_to_jiffies(30)
#define MWAN_REORDER_RING_SIZE 1024
#define MWAN_REORDER_RING_MASK (MWAN_REORDER_RING_SIZE - 1)
#define MAX_MWAN_TUNNELS 100
#define MWAN_LUT_SIZE    256
#define MWAN_FLOW_TABLE_SIZE 256
#define MWAN_FLOW_RING_SIZE  256
#define MWAN_FLOW_RING_MASK  (MWAN_FLOW_RING_SIZE - 1)
#define MWAN_L2_QUEUE_MAX_PACKETS 4096
#define MWAN_L2_QUEUE_MAX_BYTES   (8U * 1024U * 1024U)
#define MWAN_L2_DIAG_MAX_FLOWS    128
#define MWAN_L2_OWNER_BUCKETS     512
#define MWAN_L2_OWNER_WAYS        8
#define MWAN_L2_FLOW_IDLE_TIMEOUT msecs_to_jiffies(5000)

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
    spinlock_t owner_lock;
    atomic_t owner_worker;
    atomic_t pending_crypto;
    unsigned long last_seen;
    unsigned long slot_time[MWAN_FLOW_RING_SIZE];
};

/* Full 32-bit flow IDs use an associative owner table instead of sharing the
 * 8-bit reorder bucket.  Entries with pending work cannot be reclaimed. */
struct mwan_l2_flow_owner {
    u32 flow_id;
    int owner_worker;
    atomic_t pending_crypto;
    unsigned long last_seen;
    bool valid;
};

struct mwan_l2_owner_bucket {
    spinlock_t lock;
    struct mwan_l2_flow_owner ways[MWAN_L2_OWNER_WAYS];
};

/* Ordered RX/TX crypto queues per CPU. A flow bucket is owned by exactly one
 * worker in each direction, so its packets are processed serially while
 * independent buckets can run in parallel on different CPUs. */
struct mwan_l2_worker {
    struct mwan_config *cfg;
    struct sk_buff_head rx_queue;
    struct work_struct work;
    struct crypto_aead *tfm;
    struct aead_request *req;
    int cpu;

    atomic64_t queued_packets;
    atomic64_t queued_bytes;
    atomic64_t max_queued_packets;
    atomic64_t max_queued_bytes;
    atomic64_t enqueued_packets;
    atomic64_t processed_packets;
    atomic64_t dropped_packets;
    atomic64_t decrypt_failures;
    atomic64_t assigned_flows;
    atomic64_t processing_ewma_ns;
    atomic64_t work_runs;
    atomic64_t schedule_failures;
    atomic_t scheduled;
    atomic_t busy;

    /* TX has a separate queue, work item and AEAD request. RX and TX may run
     * concurrently on the same CPU, so sharing an aead_request would race. */
    struct sk_buff_head tx_queue;
    struct work_struct tx_work;
    struct crypto_aead *tx_tfm;
    struct aead_request *tx_req;
    atomic64_t tx_queued_packets;
    atomic64_t tx_queued_bytes;
    atomic64_t tx_max_queued_packets;
    atomic64_t tx_max_queued_bytes;
    atomic64_t tx_enqueued_packets;
    atomic64_t tx_processed_packets;
    atomic64_t tx_dropped_packets;
    atomic64_t tx_encrypt_failures;
    atomic64_t tx_assigned_flows;
    atomic64_t tx_processing_ewma_ns;
    atomic64_t tx_work_runs;
    atomic64_t tx_schedule_failures;
    atomic_t tx_scheduled;
    atomic_t tx_busy;

    /* Per-CPU accounting snapshots. Values are basis points (10000 == 100%).
     * Admission blocks immediately below the idle headroom threshold and
     * requires consecutive cool samples before reopening the CPU. */
    u64 cpu_prev_total;
    u64 cpu_prev_system;
    u64 cpu_prev_softirq;
    u64 cpu_prev_irq;
    u64 cpu_prev_idle;
    unsigned int cpu_cool_samples;
    atomic_t system_raw_bp;
    atomic_t system_ewma_bp;
    atomic_t softirq_raw_bp;
    atomic_t softirq_ewma_bp;
    atomic_t irq_raw_bp;
    atomic_t irq_ewma_bp;
    atomic_t idle_raw_bp;
    atomic_t idle_ewma_bp;
    atomic_t cpu_blocked;
    /* New-flow reservations made since the latest CPU accounting sample.
     * This closes the window where a burst of admissions sees the same stale
     * idle snapshot and herds onto one CPU. */
    atomic_t admissions_in_sample;
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
    
    struct mwan_per_flow_reorder flow_reorder[MWAN_FLOW_TABLE_SIZE];
    struct mwan_l2_owner_bucket rx_owners[MWAN_L2_OWNER_BUCKETS];
    struct mwan_l2_owner_bucket tx_owners[MWAN_L2_OWNER_BUCKETS];

    struct timer_list reorder_timer;
    int num_workers;
    int worker_start_cpu;
    struct mwan_l2_worker *l2_workers;

};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;
extern bool mwan_l2_diag_enabled;
extern unsigned int mwan_l2_diag_limit;
extern unsigned int mwan_l2_idle_min_pct;
extern unsigned int mwan_l2_idle_recover_pct;
extern unsigned int mwan_l2_softirq_sample_ms;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);
void mwan_reorder_timeout(struct timer_list *t);
u64 mwan_l2_next_tx_seq(u32 flow_idx);
u64 mwan_l2_next_packet_nonce(void);
void mwan_l2_diag_reset_all(void);
void mwan_l2_tx_diag_reset(void);
u32 mwan_l2_diag_generation_get(void);
u64 mwan_l2_tx_diag_flows_get(void);
u64 mwan_l2_tx_diag_zero_get(void);

#endif /* MWAN_STATE_H */
