// SPDX-License-Identifier: GPL-2.0
#include "mwan_drop_trace.h"

#if MWAN_DROP_TRACE_ENABLE

#include "mwan_state.h"

#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>

/* A power-of-two overwrite ring bounds diagnostic memory even during a drop
 * storm.  Writers never take a global lock on the packet path. */
#define MWAN_DROP_TRACE_ORDER 12U
#define MWAN_DROP_TRACE_SIZE  (1U << MWAN_DROP_TRACE_ORDER)
#define MWAN_DROP_TRACE_MASK  (MWAN_DROP_TRACE_SIZE - 1U)

struct mwan_drop_trace_event {
    u64 committed_id;
    u64 timestamp_ns;
    u64 flow_token;
    u64 queue_packets;
    u64 queue_bytes;
    u64 rate_throttle;
    u64 rate_wait_ns;
    u32 flow_seq;
    u32 flow_id;
    u32 packet_len;
    u32 pressure_bp;
    u32 drop_probability_bp;
    u32 rate_target_bp;
    u16 reason;
    u16 tunnel_idx;
    u16 tx_queue;
    s16 exec_cpu;
    s16 owner_cpu;
    s32 error;
    s32 ifindex;
    u16 system_bp;
    u16 softirq_bp;
    u16 idle_bp;
    u8 admission_blocked;
    u8 emergency_shed;
};

static struct mwan_drop_trace_event mwan_drop_ring[MWAN_DROP_TRACE_SIZE];
static atomic64_t mwan_drop_head = ATOMIC64_INIT(0);
static atomic64_t mwan_drop_clear_before = ATOMIC64_INIT(0);
static atomic64_t mwan_drop_reason_count[MWAN_DROP_REASON_MAX];

static const char *mwan_drop_reason_name(enum mwan_drop_reason reason)
{
    static const char * const names[MWAN_DROP_REASON_MAX] = {
        [MWAN_DROP_TX_OVERLOAD_SHED] = "TX_OVERLOAD_SHED",
        [MWAN_DROP_TX_QUEUE_FULL] = "TX_QUEUE_FULL",
        [MWAN_DROP_TX_FLOW_FAILED] = "TX_FLOW_FAILED",
        [MWAN_DROP_TX_OWNER_INVALID] = "TX_OWNER_INVALID",
        [MWAN_DROP_TX_WORKER_METADATA] = "TX_WORKER_METADATA",
        [MWAN_DROP_TX_WORKER_FAILED] = "TX_WORKER_FAILED",
        [MWAN_DROP_TX_CRYPTO_NO_KEY] = "TX_CRYPTO_NO_KEY",
        [MWAN_DROP_TX_CRYPTO_FAILED] = "TX_CRYPTO_FAILED",
        [MWAN_DROP_TX_PIPELINE_FULL] = "TX_PIPELINE_FULL",
        [MWAN_DROP_TX_PIPELINE_METADATA] = "TX_PIPELINE_METADATA",
        [MWAN_DROP_TX_NO_DEVICE] = "TX_NO_DEVICE",
        [MWAN_DROP_TX_DEV_XMIT] = "TX_DEV_XMIT",
        [MWAN_DROP_TX_NO_ACTIVE_TUNNEL] = "TX_NO_ACTIVE_TUNNEL",
        [MWAN_DROP_TX_TUNNEL_INVALID] = "TX_TUNNEL_INVALID",
        [MWAN_DROP_TX_CONNTRACK_REJECT] = "TX_CONNTRACK_REJECT",
        [MWAN_DROP_TX_GSO_FAILED] = "TX_GSO_FAILED",
        [MWAN_DROP_TX_MTU_DF] = "TX_MTU_DF",
        [MWAN_DROP_TX_MTU_INVALID] = "TX_MTU_INVALID",
        [MWAN_DROP_TX_FRAGMENT_FAILED] = "TX_FRAGMENT_FAILED",
        [MWAN_DROP_TX_CLEANUP] = "TX_CLEANUP",
        [MWAN_DROP_TX_PIPELINE_CLEANUP] = "TX_PIPELINE_CLEANUP",
        [MWAN_DROP_RX_SHORT] = "RX_SHORT",
        [MWAN_DROP_RX_HEADER] = "RX_HEADER",
        [MWAN_DROP_RX_INACTIVE] = "RX_INACTIVE",
        [MWAN_DROP_RX_KEY_REJECT] = "RX_KEY_REJECT",
        [MWAN_DROP_RX_FLOW_FAILED] = "RX_FLOW_FAILED",
        [MWAN_DROP_RX_OWNER_INVALID] = "RX_OWNER_INVALID",
        [MWAN_DROP_RX_QUEUE_FULL] = "RX_QUEUE_FULL",
        [MWAN_DROP_RX_WORKER_METADATA] = "RX_WORKER_METADATA",
        [MWAN_DROP_RX_CRYPTO_NO_KEY] = "RX_CRYPTO_NO_KEY",
        [MWAN_DROP_RX_AUTH_FAILED] = "RX_AUTH_FAILED",
        [MWAN_DROP_RX_CRYPTO_FAILED] = "RX_CRYPTO_FAILED",
        [MWAN_DROP_RX_PIPELINE_FULL] = "RX_PIPELINE_FULL",
        [MWAN_DROP_RX_PIPELINE_METADATA] = "RX_PIPELINE_METADATA",
        [MWAN_DROP_RX_CLEANUP] = "RX_CLEANUP",
        [MWAN_DROP_RX_PIPELINE_CLEANUP] = "RX_PIPELINE_CLEANUP",
        [MWAN_DROP_RX_REORDER_CLEANUP] = "RX_REORDER_CLEANUP",
        [MWAN_DROP_REORDER_LATE] = "REORDER_LATE",
        [MWAN_DROP_REORDER_DUPLICATE] = "REORDER_DUPLICATE",
        [MWAN_DROP_REORDER_EVICT] = "REORDER_EVICT",
        [MWAN_DROP_REORDER_GAP_TIMEOUT] = "REORDER_GAP_TIMEOUT",
        [MWAN_DROP_NETIF_RX] = "NETIF_RX_DROP",
    };

    if ((unsigned int)reason >= MWAN_DROP_REASON_MAX || !names[reason])
        return "UNKNOWN";
    return names[reason];
}

void mwan_drop_trace_record(const struct mwan_drop_trace_ctx *ctx)
{
    struct mwan_drop_trace_event *event;
    const struct mwan_l2_worker *worker;
    struct mwan_bitrate_snapshot rate = { 0 };
    u64 id;

    if (unlikely(!ctx || (unsigned int)ctx->reason >=
                           MWAN_DROP_REASON_MAX))
        return;

    id = (u64)atomic64_inc_return(&mwan_drop_head);
    event = &mwan_drop_ring[(id - 1U) & MWAN_DROP_TRACE_MASK];
    WRITE_ONCE(event->committed_id, 0);
    worker = ctx->worker;
    if (worker)
        mwan_bitrate_snapshot((struct mwan_bitrate_state *)&worker->tx_bitrate,
                              &rate);
    event->timestamp_ns = ktime_get_mono_fast_ns();
    event->flow_token = ctx->flow_token;
    event->queue_packets = ctx->queue_packets;
    event->queue_bytes = ctx->queue_bytes;
    event->rate_throttle = rate.throttle_events;
    event->rate_wait_ns = rate.wait_ns;
    event->flow_seq = ctx->flow_seq;
    event->flow_id = ctx->flow_id;
    event->packet_len = ctx->packet_len ? ctx->packet_len :
                        ctx->skb ? ctx->skb->len : 0;
    event->pressure_bp = ctx->pressure_bp;
    event->drop_probability_bp = ctx->drop_probability_bp;
    event->rate_target_bp = rate.target_bp;
    event->reason = (u16)ctx->reason;
    event->tunnel_idx = ctx->tunnel_idx;
    event->tx_queue = ctx->tx_queue;
    event->exec_cpu = (s16)raw_smp_processor_id();
    event->owner_cpu = worker ? (s16)worker->cpu : -1;
    event->error = ctx->error;
    event->ifindex = ctx->ifindex;
    event->system_bp = worker ?
        (u16)atomic_read(&worker->system_raw_bp) : 0;
    event->softirq_bp = worker ?
        (u16)atomic_read(&worker->softirq_raw_bp) : 0;
    event->idle_bp = worker ?
        (u16)atomic_read(&worker->idle_raw_bp) : 0;
    event->admission_blocked = worker ?
        (u8)atomic_read(&worker->admission_blocked) : 0;
    event->emergency_shed = worker ?
        (u8)atomic_read(&worker->emergency_shed) : 0;
    atomic64_inc(&mwan_drop_reason_count[ctx->reason]);
    smp_store_release(&event->committed_id, id);
}

void mwan_drop_trace_reset(void)
{
    u64 head = (u64)atomic64_read(&mwan_drop_head);
    int reason;

    atomic64_set(&mwan_drop_clear_before, head);
    for (reason = 0; reason < MWAN_DROP_REASON_MAX; reason++)
        atomic64_set(&mwan_drop_reason_count[reason], 0);
}

static int mwan_drop_trace_show(struct seq_file *m, void *unused)
{
    u64 clear_before = (u64)atomic64_read(&mwan_drop_clear_before);
    u64 head = (u64)atomic64_read(&mwan_drop_head);
    u64 first = head > MWAN_DROP_TRACE_SIZE ?
        head - MWAN_DROP_TRACE_SIZE : 0;
    u64 overwritten = 0;
    u64 index;
    int reason;

    (void)unused;
    if (first < clear_before)
        first = clear_before;
    if (head > clear_before + MWAN_DROP_TRACE_SIZE)
        overwritten = head - clear_before - MWAN_DROP_TRACE_SIZE;

    seq_printf(m, "drop_trace enabled=1 capacity=%u head=%llu visible=%llu overwritten=%llu\n",
               MWAN_DROP_TRACE_SIZE, head, head - first, overwritten);
    seq_puts(m, "reason_counts");
    for (reason = 0; reason < MWAN_DROP_REASON_MAX; reason++) {
        s64 count = atomic64_read(&mwan_drop_reason_count[reason]);

        if (count)
            seq_printf(m, " %s=%lld",
                       mwan_drop_reason_name(reason), count);
    }
    seq_putc(m, '\n');
    seq_puts(m, "id timestamp_ns reason exec_cpu owner_cpu token seq flow_id len q_pkts q_kib sys_bp soft_bp idle_bp blocked emergency pressure_bp drop_bp rate_bp rate_throttle rate_wait_ms err ifindex tunnel txq\n");

    for (index = first; index < head; index++) {
        const u64 expected = index + 1U;
        struct mwan_drop_trace_event copy;
        struct mwan_drop_trace_event *event =
            &mwan_drop_ring[index & MWAN_DROP_TRACE_MASK];

        if (smp_load_acquire(&event->committed_id) != expected)
            continue;
        memcpy(&copy, event, sizeof(copy));
        if (READ_ONCE(event->committed_id) != expected)
            continue;
        seq_printf(m, "%llu %llu %s %d %d %016llx ",
                   expected, copy.timestamp_ns,
                   mwan_drop_reason_name(copy.reason), copy.exec_cpu,
                   copy.owner_cpu, copy.flow_token);
        if (copy.flow_seq == MWAN_DROP_SEQ_UNKNOWN)
            seq_puts(m, "NA ");
        else
            seq_printf(m, "%u ", copy.flow_seq);
        seq_printf(m, "%08x %u %llu %llu %u %u %u %u %u %u %u %u %llu %llu %d %d ",
                   copy.flow_id, copy.packet_len, copy.queue_packets,
                   copy.queue_bytes >> 10, copy.system_bp,
                   copy.softirq_bp, copy.idle_bp, copy.admission_blocked,
                   copy.emergency_shed, copy.pressure_bp,
                   copy.drop_probability_bp, copy.rate_target_bp,
                   copy.rate_throttle,
                   div_u64(copy.rate_wait_ns, NSEC_PER_MSEC), copy.error,
                   copy.ifindex);
        if (copy.tunnel_idx == MWAN_DROP_TUNNEL_UNKNOWN)
            seq_puts(m, "NA ");
        else
            seq_printf(m, "%u ", copy.tunnel_idx);
        if (copy.tx_queue == MWAN_DROP_TXQ_UNKNOWN)
            seq_puts(m, "NA\n");
        else
            seq_printf(m, "%u\n", copy.tx_queue);
    }
    return 0;
}

static int mwan_drop_trace_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_drop_trace_show, inode->i_private);
}

static int mwan_drop_summary_show(struct seq_file *m, void *unused)
{
    u64 clear_before = (u64)atomic64_read(&mwan_drop_clear_before);
    u64 head = (u64)atomic64_read(&mwan_drop_head);
    u64 since_reset = head - clear_before;
    u64 overwritten = since_reset > MWAN_DROP_TRACE_SIZE ?
        since_reset - MWAN_DROP_TRACE_SIZE : 0;
    int reason;

    (void)unused;
    seq_printf(m, "events=%llu retained=%llu overwritten=%llu\n",
               since_reset, min_t(u64, since_reset, MWAN_DROP_TRACE_SIZE),
               overwritten);
    for (reason = 0; reason < MWAN_DROP_REASON_MAX; reason++) {
        s64 count = atomic64_read(&mwan_drop_reason_count[reason]);

        if (count)
            seq_printf(m, "%s %lld\n",
                       mwan_drop_reason_name(reason), count);
    }
    return 0;
}

static int mwan_drop_summary_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_drop_summary_show, inode->i_private);
}

static ssize_t mwan_drop_trace_write(struct file *file,
                                     const char __user *buffer,
                                     size_t count, loff_t *ppos)
{
    bool reset;
    int err;

    (void)file;
    (void)ppos;
    err = kstrtobool_from_user(buffer, count, &reset);
    if (err)
        return err;
    if (reset)
        mwan_drop_trace_reset();
    return count;
}

static const struct file_operations mwan_drop_trace_fops = {
    .owner = THIS_MODULE,
    .open = mwan_drop_trace_open,
    .read = seq_read,
    .write = mwan_drop_trace_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static const struct file_operations mwan_drop_summary_fops = {
    .owner = THIS_MODULE,
    .open = mwan_drop_summary_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

void mwan_drop_trace_debugfs_init(struct dentry *parent)
{
    int reason;

    BUILD_BUG_ON(MWAN_DROP_TRACE_SIZE & MWAN_DROP_TRACE_MASK);
    for (reason = 0; reason < MWAN_DROP_REASON_MAX; reason++)
        atomic64_set(&mwan_drop_reason_count[reason], 0);
    if (parent)
        debugfs_create_file("drop_trace", 0644, parent, NULL,
                            &mwan_drop_trace_fops);
    if (parent)
        debugfs_create_file("drop_summary", 0444, parent, NULL,
                            &mwan_drop_summary_fops);
}

#endif /* MWAN_DROP_TRACE_ENABLE */
