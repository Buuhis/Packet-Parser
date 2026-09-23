/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MWAN_DROP_TRACE_H
#define MWAN_DROP_TRACE_H

#include <linux/types.h>

struct dentry;
struct sk_buff;
struct mwan_l2_worker;

/* Compile-time diagnostic switch.  Set to 0 after the loss investigation,
 * rebuild and reload; calls then compile to no-ops. */
#define MWAN_DROP_TRACE_ENABLE 1

enum mwan_drop_reason {
    MWAN_DROP_TX_OVERLOAD_SHED = 0,
    MWAN_DROP_TX_QUEUE_FULL,
    MWAN_DROP_TX_FLOW_FAILED,
    MWAN_DROP_TX_OWNER_INVALID,
    MWAN_DROP_TX_WORKER_METADATA,
    MWAN_DROP_TX_WORKER_FAILED,
    MWAN_DROP_TX_CRYPTO_NO_KEY,
    MWAN_DROP_TX_CRYPTO_FAILED,
    MWAN_DROP_TX_PIPELINE_FULL,
    MWAN_DROP_TX_PIPELINE_METADATA,
    MWAN_DROP_TX_NO_DEVICE,
    MWAN_DROP_TX_DEV_XMIT,
    MWAN_DROP_TX_NO_ACTIVE_TUNNEL,
    MWAN_DROP_TX_TUNNEL_INVALID,
    MWAN_DROP_TX_CONNTRACK_REJECT,
    MWAN_DROP_TX_GSO_FAILED,
    MWAN_DROP_TX_MTU_DF,
    MWAN_DROP_TX_MTU_INVALID,
    MWAN_DROP_TX_FRAGMENT_FAILED,
    MWAN_DROP_TX_CLEANUP,
    MWAN_DROP_TX_PIPELINE_CLEANUP,
    MWAN_DROP_RX_SHORT,
    MWAN_DROP_RX_HEADER,
    MWAN_DROP_RX_INACTIVE,
    MWAN_DROP_RX_KEY_REJECT,
    MWAN_DROP_RX_FLOW_FAILED,
    MWAN_DROP_RX_OWNER_INVALID,
    MWAN_DROP_RX_QUEUE_FULL,
    MWAN_DROP_RX_WORKER_METADATA,
    MWAN_DROP_RX_CRYPTO_NO_KEY,
    MWAN_DROP_RX_AUTH_FAILED,
    MWAN_DROP_RX_CRYPTO_FAILED,
    MWAN_DROP_RX_PIPELINE_FULL,
    MWAN_DROP_RX_PIPELINE_METADATA,
    MWAN_DROP_RX_CLEANUP,
    MWAN_DROP_RX_PIPELINE_CLEANUP,
    MWAN_DROP_RX_REORDER_CLEANUP,
    MWAN_DROP_REORDER_LATE,
    MWAN_DROP_REORDER_DUPLICATE,
    MWAN_DROP_REORDER_EVICT,
    MWAN_DROP_REORDER_GAP_TIMEOUT,
    MWAN_DROP_NETIF_RX,
    MWAN_DROP_REASON_MAX,
};

#define MWAN_DROP_SEQ_UNKNOWN U32_MAX
#define MWAN_DROP_TUNNEL_UNKNOWN U16_MAX
#define MWAN_DROP_TXQ_UNKNOWN U16_MAX

struct mwan_drop_trace_ctx {
    enum mwan_drop_reason reason;
    const struct mwan_l2_worker *worker;
    const struct sk_buff *skb;
    u64 flow_token;
    u32 flow_seq;
    u32 flow_id;
    u32 packet_len;
    u64 queue_packets;
    u64 queue_bytes;
    u32 pressure_bp;
    u32 drop_probability_bp;
    int error;
    int ifindex;
    u16 tunnel_idx;
    u16 tx_queue;
};

#if MWAN_DROP_TRACE_ENABLE
void mwan_drop_trace_record(const struct mwan_drop_trace_ctx *ctx);
void mwan_drop_trace_debugfs_init(struct dentry *parent);
void mwan_drop_trace_reset(void);
#else
static inline void
mwan_drop_trace_record(const struct mwan_drop_trace_ctx *ctx)
{
    (void)ctx;
}

static inline void mwan_drop_trace_debugfs_init(struct dentry *parent)
{
    (void)parent;
}

static inline void mwan_drop_trace_reset(void)
{
}
#endif

#endif /* MWAN_DROP_TRACE_H */
