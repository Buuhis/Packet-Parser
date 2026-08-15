#ifndef MWAN_L2_MULTICORE_H
#define MWAN_L2_MULTICORE_H

#include <linux/skbuff.h>
#include <linux/types.h>

struct mwan_config;
struct mwan_l2_worker;
struct seq_file;
struct work_struct;

/* skb->cb metadata is owned by the multicore dispatcher while a packet is
 * queued. RX/TX clear it before handing the packet to the network stack. */
struct mwan_l2_rx_cb {
    u64 dispatch_flow_seq;
    u64 dispatch_nonce;
    u64 diag_cookie;
    u32 flow_idx;
    u32 accounted_bytes;
    u32 dispatch_flow_id;
    u32 diag_check;
    u32 diag_magic;
    u16 dispatch_headlen;
    u8 dispatch_flags;
    u8 reserved;
};

#define MWAN_L2_RX_CB_NONLINEAR BIT(0)
#define MWAN_L2_RX_CB_MAGIC     0x4c324443U
#define MWAN_L2_RX_CB(skb) ((struct mwan_l2_rx_cb *)((skb)->cb))

struct mwan_l2_tx_cb {
    u64 flow_seq;
    u32 flow_id;
    u32 accounted_bytes;
    u16 tunnel_idx;
    u16 magic;
};

#define MWAN_L2_TX_CB_MAGIC 0x4d54U
#define MWAN_L2_TX_CB(skb) ((struct mwan_l2_tx_cb *)((skb)->cb))

struct mwan_l2_select_diag {
    unsigned int eligible_cpus;
    unsigned int chosen_idle_bp;
    u64 chosen_queue_packets;
    u64 chosen_queue_bytes;
    u64 chosen_assigned_flows;
    unsigned int chosen_admissions;
    bool spread_first;
    bool ran;
};

int mwan_l2_multicore_init(void);
void mwan_l2_multicore_cleanup(void);
int mwan_l2_workers_init(struct mwan_config *cfg);
void mwan_l2_workers_cleanup(struct mwan_config *cfg);

int mwan_l2_rx_owner_acquire(struct mwan_config *cfg, u32 flow_id,
                             int *owner_worker,
                             struct mwan_l2_select_diag *diag);
int mwan_l2_tx_owner_acquire(struct mwan_config *cfg, u32 flow_id,
                             int *owner_worker);
void mwan_l2_flow_owner_complete(struct mwan_config *cfg, u32 flow_id,
                                 bool tx);
bool mwan_l2_schedule_rx_worker(struct mwan_l2_worker *worker);
bool mwan_l2_schedule_tx_worker(struct mwan_l2_worker *worker);

void mwan_l2_rx_worker_fn(struct work_struct *work);
void mwan_l2_tx_worker_fn(struct work_struct *work);
u64 mwan_l2_worker_score(const struct mwan_l2_worker *worker);

void mwan_l2_multicore_diag_reset(void);
void mwan_l2_multicore_diag_show(struct seq_file *m);

#endif /* MWAN_L2_MULTICORE_H */
