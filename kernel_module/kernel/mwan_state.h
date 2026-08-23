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
#include <linux/if_ether.h>
#include <linux/refcount.h>
#include <linux/list.h>
#include "mwan_proto.h"

#define MWAN_REORDER_TIMEOUT       msecs_to_jiffies(30)
#define MAX_MWAN_TUNNELS 100
#define MWAN_LUT_SIZE    256
#define MWAN_FLOW_HASH_SIZE 1024
#define MWAN_FLOW_RING_SIZE  256
#define MWAN_FLOW_RING_MASK  (MWAN_FLOW_RING_SIZE - 1)
#define MWAN_FLOW_MAX_ACTIVE 4096
#define MWAN_FLOW_IDLE_TIMEOUT msecs_to_jiffies(60000)
#define MWAN_FLOW_CLOSING_TIMEOUT msecs_to_jiffies(2000)
#define MWAN_FLOW_GC_INTERVAL msecs_to_jiffies(5000)
#define MWAN_L2_QUEUE_MAX_PACKETS 4096
#define MWAN_L2_QUEUE_MAX_BYTES   (8U * 1024U * 1024U)
#define MWAN_L2_DIAG_MAX_FLOWS    128
#define MWAN_FLOW_COOKIE_MASK GENMASK_ULL(55, 0)
#define MWAN_FLOW_KEY_ID_SHIFT 56

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

    /* Caching fields for performance */
    struct net_device *dev;
    spinlock_t gateway_mac_lock;
    u8 gateway_mac[ETH_ALEN];
    bool mac_resolved;
    bool is_ethernet;
    enum mwan_encap_type encap_type;
};

struct mwan_l2_flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u32 fallback_hash;
    u8 protocol;
    u8 reserved[3];
};

struct mwan_l2_tx_flow {
    struct hlist_node node;
    struct mwan_l2_flow_key key;
    refcount_t refs;
    u64 flow_token;
    atomic_t next_seq;
    atomic_t pending_crypto;
    /* Serializes admission + sequence allocation + queue insertion for one
     * flow.  A sequence number is consumed only after the packet is certain
     * to enter its sticky owner's FIFO. */
    spinlock_t submit_lock;
    int owner_worker;
    unsigned long last_seen;
    bool closing;
};

struct mwan_l2_rx_flow {
    struct hlist_node node;
    refcount_t refs;
    u64 flow_token;
    u32 expected_seq;
    atomic_t pending_crypto;
    int owner_worker;
    unsigned long last_seen;
    bool closing;
    bool stopping;
    struct mwan_l2_flow_manager *manager;
    spinlock_t reorder_lock;
    struct timer_list reorder_timer;
    struct sk_buff *ring[MWAN_FLOW_RING_SIZE];
    unsigned long slot_time[MWAN_FLOW_RING_SIZE];
};

/* skb->cb metadata while an encrypted RX frame waits for its sticky worker. */
struct mwan_l2_rx_cb {
    uintptr_t flow_ptr;
    u64 dispatch_flow_token;
    u64 dispatch_nonce;
    u64 diag_cookie;
    u32 dispatch_flow_seq;
    u32 accounted_bytes;
    u32 diag_check;
    u16 dispatch_headlen;
    u8 dispatch_flags;
    u8 diag_magic;
};

#define MWAN_L2_RX_CB_NONLINEAR BIT(0)
#define MWAN_L2_RX_CB_MAGIC     0x4cU
#define MWAN_L2_RX_CB(skb) ((struct mwan_l2_rx_cb *)((skb)->cb))

static inline u32 mwan_l2_rx_cb_checksum(const struct mwan_l2_rx_cb *cb)
{
    return lower_32_bits(cb->flow_ptr) ^ upper_32_bits(cb->flow_ptr) ^
           lower_32_bits(cb->dispatch_flow_token) ^
           upper_32_bits(cb->dispatch_flow_token) ^
           cb->accounted_bytes ^ cb->dispatch_flow_seq ^
           lower_32_bits(cb->dispatch_nonce) ^
           upper_32_bits(cb->dispatch_nonce) ^
           lower_32_bits(cb->diag_cookie) ^
           upper_32_bits(cb->diag_cookie) ^ cb->dispatch_headlen ^
           cb->dispatch_flags ^ 0x6d77616eU;
}

struct mwan_l2_tx_cb {
    uintptr_t flow_ptr;
    u64 flow_token;
    u32 flow_seq;
    u32 accounted_bytes;
    u32 check;
    u16 tunnel_idx;
    u16 magic;
    u8 encap_type;
    u8 reserved[3];
};

#define MWAN_L2_TX_CB_MAGIC 0x4d54U
#define MWAN_L2_TX_CB(skb) ((struct mwan_l2_tx_cb *)((skb)->cb))

struct mwan_l2_flow_bucket {
    struct hlist_head head;
    spinlock_t lock;
};

struct mwan_l2_flow_manager {
    struct mwan_l2_flow_bucket tx[MWAN_FLOW_HASH_SIZE];
    struct mwan_l2_flow_bucket rx[MWAN_FLOW_HASH_SIZE];
    atomic_t tx_count;
    atomic_t rx_count;
    atomic64_t tx_created;
    atomic64_t tx_expired;
    atomic64_t rx_created;
    atomic64_t rx_expired;
    atomic64_t table_full;
    atomic64_t reorder_late;
    atomic64_t reorder_duplicate;
    atomic64_t reorder_too_far;
    atomic64_t reorder_timeouts;
    struct delayed_work gc_work;
    struct mwan_config *cfg;
    bool stopping;
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
    struct crypto_aead *prev_tfm;
    struct aead_request *prev_req;
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
    atomic64_t tx_xmit_failures;
    atomic64_t tx_assigned_flows;
    atomic64_t tx_processing_ewma_ns;
    atomic64_t tx_work_runs;
    atomic64_t tx_schedule_failures;
    atomic_t tx_scheduled;
    atomic_t tx_busy;

    /* Per-CPU admission signals from kernel CPU accounting.  Values are
     * basis points (10000 == 100%).  The sampler is the only writer; RX/TX
     * admission and shedding consume atomic snapshots. */
    u64 cpu_prev_total;
    u64 cpu_prev_system;
    u64 cpu_prev_softirq;
    u64 cpu_prev_idle;
    unsigned int cpu_cool_samples;
    atomic_t system_raw_bp;
    atomic_t system_ewma_bp;
    atomic_t softirq_raw_bp;
    atomic_t softirq_ewma_bp;
    atomic_t idle_raw_bp;
    atomic_t idle_ewma_bp;
    atomic_t busy_raw_bp;
    atomic_t busy_ewma_bp;
    atomic_t admission_blocked;
    atomic_t emergency_shed;
    atomic64_t tx_ecn_marked;
    atomic64_t rx_ecn_marked;
    atomic64_t tx_overload_dropped;
    atomic64_t tx_control_preserved;
};

struct mwan_config {
    u32 node_id;
    u32 num_tunnels;
    u32 total_weight; /* Pre-calculated total weight */
    
    /* Lookup table for O(1) weight-proportional tunnel selection */
    u8  tunnel_idx_lut[MWAN_LUT_SIZE];
    
    struct mwan_tunnel tunnels[MAX_MWAN_TUNNELS];

    /* Encryption (AES-GCM) */
    bool encrypt_on;
    u8   encrypt_layer;                   /* 2=L2 (MACsec), 3=L3 (Overlay) */
    u8   encrypt_type;                    /* enum mwan_crypt_type */
    u8   encrypt_key[MWAN_MAX_KEY_LEN];
    u8   encrypt_key_len;                 /* 16 (128-bit) or 32 (256-bit) */
    u8   encrypt_salt[MWAN_SALT_LEN];
    struct crypto_aead *tfm;              /* Crypto transform context */
    struct crypto_aead *prev_tfm;         /* Previous PQC key during grace */
    
    struct mwan_l2_flow_manager flows;
    u8 key_id;
    u8 prev_key_id;
    u8 prev_key[MWAN_MAX_KEY_LEN];
    u8 prev_key_len;
    bool prev_key_valid;
    int num_workers;
    int worker_start_cpu;
    struct mwan_l2_worker *l2_workers;

};

/* Global pointer to the current active configuration */
extern struct mwan_config __rcu *g_mwan_cfg;
extern bool mwan_l2_diag_enabled;
extern bool mwan_fw_diag_enabled;
extern unsigned int mwan_l2_diag_limit;
extern unsigned int mwan_l2_softirq_high_pct;
extern unsigned int mwan_l2_softirq_low_pct;
extern unsigned int mwan_l2_softirq_sample_ms;
extern unsigned int mwan_l2_idle_unblock_pct;
extern unsigned int mwan_l2_emergency_pct;
extern unsigned int mwan_l2_max_shed_pct;

/* API Functions */
void mwan_state_init(void);
void mwan_state_cleanup(void);
int mwan_state_update(struct mwan_config *new_cfg);
u64 mwan_next_packet_nonce(void);
int mwan_l2_workers_init(struct mwan_config *cfg);
void mwan_l2_workers_cleanup(struct mwan_config *cfg);
int mwan_l2_select_tx_worker(const struct mwan_config *cfg, u32 flow_id,
                             int current_owner,
                             bool allow_blocked_fallback);
int mwan_l2_select_rx_worker(const struct mwan_config *cfg, u32 flow_id,
                             int current_owner,
                             bool allow_blocked_fallback);
bool mwan_l2_schedule_tx_worker(struct mwan_l2_worker *worker);
void mwan_l2_tx_worker_fn(struct work_struct *work);
void mwan_l2_rx_worker_fn(struct work_struct *work);
void mwan_multicore_worker_cpu_init(struct mwan_l2_worker *worker);
int mwan_multicore_init(void);
void mwan_multicore_cleanup(void);
u64 mwan_multicore_worker_score(const struct mwan_l2_worker *worker);
u64 mwan_multicore_admitted_get(void);
u64 mwan_multicore_no_eligible_get(void);
void mwan_multicore_diag_reset(void);
void mwan_l2_diag_reset_all(void);
void mwan_l2_tx_diag_reset(void);
u32 mwan_l2_diag_generation_get(void);
u64 mwan_l2_tx_diag_flows_get(void);
u64 mwan_l2_tx_diag_zero_get(void);

int mwan_l2_flow_manager_init(struct mwan_config *cfg);
void mwan_l2_flow_manager_start(struct mwan_config *cfg);
void mwan_l2_flow_manager_stop(struct mwan_config *cfg);
struct mwan_l2_tx_flow *
mwan_l2_tx_flow_get(struct mwan_config *cfg,
                    const struct mwan_l2_flow_key *key, u32 flow_hash,
                    bool control_packet);
void mwan_l2_tx_flow_put(struct mwan_l2_tx_flow *flow);
void mwan_l2_tx_flow_touch(struct mwan_l2_tx_flow *flow, bool closing);
u32 mwan_l2_tx_flow_next_seq(struct mwan_l2_tx_flow *flow);
bool mwan_l2_tx_flow_release_queued(struct mwan_config *cfg,
                                   const struct mwan_l2_flow_key *key,
                                   int owner_worker);
struct mwan_l2_rx_flow *
mwan_l2_rx_flow_get(struct mwan_config *cfg, u64 flow_token, u32 first_seq);
void mwan_l2_rx_flow_put(struct mwan_l2_rx_flow *flow);
void mwan_l2_rx_flow_touch(struct mwan_l2_rx_flow *flow, bool closing);
bool mwan_l2_rx_flow_release_queued(struct mwan_config *cfg, u64 flow_token,
                                   int owner_worker);
void mwan_l2_rx_flow_deliver(struct mwan_l2_rx_flow *flow,
                             struct sk_buff *skb, u32 flow_seq);

#endif /* MWAN_STATE_H */
