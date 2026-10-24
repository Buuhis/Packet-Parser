#include "mwan_state.h"
#include "mwan_drop_trace.h"
#include "mwan_multicore.h"
#include "mwan_tunnel_balance.h"

#include <linux/cpu.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/jhash.h>
#include <linux/log2.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/version.h>

static void mwan_l2_flow_gc_workfn(struct work_struct *work);
static void mwan_l2_tx_dispatch_workfn(struct work_struct *work);
static void mwan_l2_tx_emit_workfn(struct work_struct *work);

static void mwan_l2_atomic64_update_max(atomic64_t *maximum, u64 value)
{
    s64 old = atomic64_read(maximum);

    while (value > (u64)old) {
        s64 observed = atomic64_cmpxchg(maximum, old, (s64)value);

        if (observed == old)
            break;
        old = observed;
    }
}

static const struct mwan_l2_worker *
mwan_reorder_owner(const struct mwan_l2_rx_flow *flow)
{
    const struct mwan_config *cfg;

    if (!flow || !flow->manager)
        return NULL;
    cfg = flow->manager->cfg;
    if (!cfg || !cfg->l2_workers || flow->owner_worker < 0 ||
        flow->owner_worker >= cfg->num_workers)
        return NULL;
    return &cfg->l2_workers[flow->owner_worker];
}

static void mwan_reorder_drop_trace(enum mwan_drop_reason reason,
                                    const struct mwan_l2_rx_flow *flow,
                                    const struct sk_buff *skb, u32 flow_seq,
                                    u32 packet_len, int ifindex, int error)
{
    const struct mwan_drop_trace_ctx ctx = {
        .reason = reason,
        .worker = mwan_reorder_owner(flow),
        .skb = skb,
        .flow_token = flow ? flow->flow_token : 0,
        .flow_seq = flow_seq,
        .flow_id = flow ? lower_32_bits(flow->flow_token) : 0,
        .packet_len = packet_len,
        .queue_packets = flow ? flow->reorder_queued : 0,
        .error = error,
        .ifindex = ifindex ? ifindex :
                   skb && skb->dev ? skb->dev->ifindex : 0,
        .tunnel_idx = MWAN_DROP_TUNNEL_UNKNOWN,
        .tx_queue = MWAN_DROP_TXQ_UNKNOWN,
    };

    mwan_drop_trace_record(&ctx);
}

static bool mwan_l2_reorder_slot_expired(u32 timestamp)
{
    u32 expires = timestamp + (u32)MWAN_REORDER_TIMEOUT;

    return (s32)((u32)jiffies - expires) >= 0;
}

/* Called with reorder_lock held.  Once a gap has started, newly arriving
 * packets must not postpone its deadline.  Otherwise a continuous stream can
 * keep mod_timer(now + timeout) moving forever and fill even a large ring
 * before the timeout callback gets a chance to advance expected_seq. */
static void mwan_l2_reorder_arm_locked(struct mwan_l2_rx_flow *flow)
{
    u32 delay = (u32)MWAN_REORDER_TIMEOUT;
    u32 now = (u32)jiffies;
    int i;

    if (READ_ONCE(flow->stopping) || !flow->reorder_queued ||
        timer_pending(&flow->reorder_timer))
        return;

    for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
        s32 remaining;

        if (!flow->ring[i])
            continue;
        remaining = (s32)(flow->slot_time[i] +
                          (u32)MWAN_REORDER_TIMEOUT - now);
        if (remaining <= 0) {
            delay = 1;
            break;
        }
        delay = min_t(u32, delay, (u32)remaining);
    }
    mod_timer(&flow->reorder_timer, jiffies + max_t(u32, delay, 1));
}

static void mwan_l2_timer_delete_sync(struct timer_list *timer)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
    timer_delete_sync(timer);
#else
    del_timer_sync(timer);
#endif
}

static u32 mwan_l2_tx_bucket(const struct mwan_l2_flow_key *key)
{
    return jhash(key, sizeof(*key), 0x6d77616eU) &
           (MWAN_FLOW_HASH_SIZE - 1);
}

static u32 mwan_l2_rx_bucket(u64 flow_token)
{
    return hash_64(flow_token & MWAN_FLOW_COOKIE_MASK,
                   ilog2(MWAN_FLOW_HASH_SIZE));
}

static bool mwan_l2_flow_key_equal(const struct mwan_l2_flow_key *a,
                                   const struct mwan_l2_flow_key *b)
{
    return !memcmp(a, b, sizeof(*a));
}

static u64 mwan_l2_new_flow_token(void)
{
    u64 cookie;

    do {
        cookie = get_random_u64() & MWAN_FLOW_COOKIE_MASK;
    } while (!cookie || cookie == MWAN_L2_DISCOVERY_COOKIE);
    return cookie;
}

static bool mwan_l2_flow_expired(unsigned long last_seen, bool closing)
{
    unsigned long timeout = closing ? MWAN_FLOW_CLOSING_TIMEOUT :
                                      MWAN_FLOW_IDLE_TIMEOUT;

    return time_after(jiffies, last_seen + timeout);
}

static bool mwan_l2_tx_balance_inactive(const struct mwan_l2_tx_flow *flow)
{
    if (READ_ONCE(flow->closing))
        return true;
    return time_after(jiffies, READ_ONCE(flow->last_seen) +
                               MWAN_FLOW_BALANCE_IDLE_TIMEOUT);
}

static bool mwan_l2_tx_flow_idle(const struct mwan_l2_tx_flow *flow)
{
    return !atomic_read(&flow->pending_crypto) &&
           skb_queue_empty(&flow->backlog);
}

static void mwan_l2_tx_flow_free(struct mwan_l2_tx_flow *flow)
{
    u16 tunnel_idx;

    if (!flow)
        return;
    for (tunnel_idx = 0; tunnel_idx < flow->num_streams; tunnel_idx++) {
        struct mwan_l2_tx_stream *stream = flow->streams[tunnel_idx];
        u16 slot;

        if (!stream)
            continue;
        WARN_ON_ONCE(work_busy(&stream->emit_work));
        for (slot = 0; slot < stream->ring_size; slot++)
            kfree_skb(stream->slots[slot].skb);
        kfree(stream);
    }
    kfree(flow->streams);
    kfree(flow);
}

static void mwan_l2_tx_balance_deactivate(struct mwan_config *cfg,
                                          struct mwan_l2_tx_flow *flow)
{
    if (atomic_cmpxchg(&flow->balance_counted, 1, 0) == 1)
        mwan_tunnel_balance_release_flow(cfg,
                                         READ_ONCE(flow->tunnel_idx));
}

static bool mwan_l2_tx_worker_inactive(const struct mwan_l2_tx_flow *flow)
{
    if (READ_ONCE(flow->closing))
        return true;
    if (flow->key.protocol != IPPROTO_UDP)
        return false;
    return time_after(jiffies, READ_ONCE(flow->last_seen) +
                               MWAN_FLOW_BALANCE_IDLE_TIMEOUT);
}

static void mwan_l2_tx_worker_deactivate(struct mwan_config *cfg,
                                         struct mwan_l2_tx_flow *flow)
{
    int owner;

    if (!cfg || !flow ||
        atomic_cmpxchg(&flow->worker_counted, 1, 0) != 1)
        return;
    owner = READ_ONCE(flow->owner_worker);
    if (cfg->l2_workers && owner >= 0 && owner < cfg->num_workers)
        atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
    atomic64_inc(&cfg->flows.tx_worker_deactivated);
}

/* The caller holds reorder_lock, so flushing here preserves global flow
 * order while amortizing the home-CPU output queue lock and work scheduling. */
static void mwan_l2_rx_batch_append(struct mwan_l2_rx_flow *flow,
                                    struct sk_buff_head *batch,
                                    struct sk_buff *skb)
{
    __skb_queue_tail(batch, skb);
    if (batch->qlen >= MWAN_L2_RX_OUTPUT_BATCH)
        mwan_l2_rx_reinject_batch(flow, batch);
}

/* Called with both the TX flow bucket and submit locks held. An inactive UDP
 * mapping may select a fresh worker only after its old queue references
 * reached zero. The flow object, tunnel and sequence stay intact, so this is
 * not migration of a live flow. */
static bool mwan_l2_tx_worker_reactivate(struct mwan_config *cfg,
                                         struct mwan_l2_tx_flow *flow,
                                         u32 flow_hash,
                                         bool control_packet)
{
    int old_owner;
    int owner;

    if (atomic_read(&flow->worker_counted))
        return true;
    old_owner = READ_ONCE(flow->owner_worker);
    if (READ_ONCE(flow->closing) || !mwan_l2_tx_flow_idle(flow)) {
        owner = old_owner;
        if (!cfg->l2_workers || owner < 0 || owner >= cfg->num_workers ||
            !cpu_online(cfg->l2_workers[owner].cpu))
            return false;
        atomic64_inc(&cfg->l2_workers[owner].tx_assigned_flows);
    } else {
        owner = mwan_l2_select_tx_worker(cfg, flow_hash, -1,
                                         control_packet);
        if (owner < 0)
            return false;
    }
    WRITE_ONCE(flow->owner_worker, owner);
    atomic_set(&flow->worker_counted, 1);
    atomic64_inc(&cfg->flows.tx_worker_reactivated);
    if (owner != old_owner)
        atomic64_inc(&cfg->flows.tx_worker_reselected);
    return true;
}

static void mwan_l2_rx_reorder_timeout(struct timer_list *timer)
{
    struct mwan_l2_rx_flow *flow =
        container_of(timer, struct mwan_l2_rx_flow, reorder_timer);
    u32 first_missing = 0;
    u32 next_expected;
    u32 skipped = 0;
    bool restart = false;
    struct sk_buff_head batch;
    int i;

    __skb_queue_head_init(&batch);
    spin_lock_bh(&flow->reorder_lock);
    while (1) {
        u32 slot = flow->expected_seq & MWAN_FLOW_RING_MASK;
        struct sk_buff *skb = flow->ring[slot];

        if (skb && flow->slot_seq[slot] == flow->expected_seq) {
            flow->ring[slot] = NULL;
            flow->slot_seq[slot] = 0;
            flow->slot_time[slot] = 0;
            flow->reorder_queued--;
            flow->expected_seq++;
            mwan_l2_rx_batch_append(flow, &batch, skb);
            continue;
        }

        for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
            if (flow->ring[i] &&
                mwan_l2_reorder_slot_expired(flow->slot_time[i]))
                break;
        }
        if (i == MWAN_FLOW_RING_SIZE)
            break;
        if (!skipped)
            first_missing = flow->expected_seq;
        mwan_reorder_drop_trace(MWAN_DROP_REORDER_GAP_TIMEOUT, flow, NULL,
                                flow->expected_seq, 0, 0, -ETIMEDOUT);
        skipped++;
        flow->expected_seq++;
        atomic64_inc(&flow->manager->reorder_timeouts);
    }

    restart = flow->reorder_queued != 0;
    if (restart)
        mwan_l2_reorder_arm_locked(flow);
    next_expected = flow->expected_seq;
    spin_unlock_bh(&flow->reorder_lock);

    if (!skb_queue_empty(&batch))
        mwan_l2_rx_reinject_batch(flow, &batch);

    if (skipped && READ_ONCE(mwan_l2_diag_enabled))
        pr_warn_ratelimited("mwan_kmod: L2D REORDER_TIMEOUT token=%016llx first_missing=%u skipped=%u next_expected=%u timeout_ms=%u\n",
                            flow->flow_token, first_missing, skipped,
                            next_expected,
                            jiffies_to_msecs(MWAN_REORDER_TIMEOUT));
}

int mwan_l2_flow_manager_init(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return -EINVAL;
    /* Slot selection uses a bit mask throughout the reorder datapath. */
    BUILD_BUG_ON(MWAN_FLOW_RING_SIZE & (MWAN_FLOW_RING_SIZE - 1));
    cfg->flows.cfg = cfg;
    cfg->flows.stopping = false;
    INIT_DELAYED_WORK(&cfg->flows.gc_work, mwan_l2_flow_gc_workfn);
    INIT_DELAYED_WORK(&cfg->flows.tx_dispatch_work,
                      mwan_l2_tx_dispatch_workfn);
    atomic_set(&cfg->flows.tx_count, 0);
    atomic_set(&cfg->flows.rx_count, 0);
    atomic64_set(&cfg->flows.tx_created, 0);
    atomic64_set(&cfg->flows.tx_expired, 0);
    atomic64_set(&cfg->flows.tx_worker_deactivated, 0);
    atomic64_set(&cfg->flows.tx_worker_reactivated, 0);
    atomic64_set(&cfg->flows.tx_worker_reselected, 0);
    atomic64_set(&cfg->flows.tx_degraded_admitted, 0);
    atomic64_set(&cfg->flows.tx_recovery_updated, 0);
    atomic64_set(&cfg->flows.tx_recovery_moved, 0);
    atomic64_set(&cfg->flows.tx_ipsec_sa_created, 0);
    atomic64_set(&cfg->flows.tx_ipsec_fragment_created, 0);
    atomic64_set(&cfg->flows.rx_created, 0);
    atomic64_set(&cfg->flows.rx_expired, 0);
    atomic64_set(&cfg->flows.table_full, 0);
    atomic64_set(&cfg->flows.reorder_late, 0);
    atomic64_set(&cfg->flows.reorder_duplicate, 0);
    atomic64_set(&cfg->flows.reorder_too_far, 0);
    atomic64_set(&cfg->flows.reorder_timeouts, 0);
    atomic64_set(&cfg->flows.reorder_resync, 0);
    atomic64_set(&cfg->flows.reorder_resync_skipped, 0);
    atomic64_set(&cfg->flows.reorder_resync_flushed, 0);
    atomic64_set(&cfg->flows.reorder_resync_preserved, 0);
    atomic64_set(&cfg->flows.tx_pipeline_promoted, 0);
    atomic64_set(&cfg->flows.rx_pipeline_promoted, 0);
    atomic64_set(&cfg->flows.tx_pipeline_dropped, 0);
    atomic64_set(&cfg->flows.rx_pipeline_dropped, 0);
    atomic64_set(&cfg->flows.tx_backlog_packets, 0);
    atomic64_set(&cfg->flows.tx_backlog_bytes, 0);
    atomic_set(&cfg->flows.tx_backlog_flows, 0);
    spin_lock_init(&cfg->flows.tx_backlog_lock);
    atomic64_set(&cfg->flows.tx_emit_batches, 0);
    atomic64_set(&cfg->flows.tx_emit_packets, 0);
    atomic64_set(&cfg->flows.tx_emit_tombstones, 0);
    atomic64_set(&cfg->flows.tx_emit_max_batch, 0);
    atomic64_set(&cfg->flows.tx_emit_xmit_failures, 0);
    atomic64_set(&cfg->flows.tx_emit_schedule_collisions, 0);
    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&cfg->flows.tx[i].head);
        spin_lock_init(&cfg->flows.tx[i].lock);
        INIT_HLIST_HEAD(&cfg->flows.rx[i].head);
        spin_lock_init(&cfg->flows.rx[i].lock);
    }
    cfg->flows.tx_emit_wq = alloc_workqueue(
        "mwan_emit", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!cfg->flows.tx_emit_wq)
        return -ENOMEM;
    return 0;
}

void mwan_l2_tx_emit_stop(struct mwan_config *cfg)
{
    struct workqueue_struct *wq;

    if (!cfg)
        return;
    wq = xchg(&cfg->flows.tx_emit_wq, NULL);
    if (wq)
        destroy_workqueue(wq);
}

static void mwan_l2_tx_dispatch_workfn(struct work_struct *work)
{
    struct mwan_l2_flow_manager *manager =
        container_of(to_delayed_work(work), struct mwan_l2_flow_manager,
                     tx_dispatch_work);
    struct mwan_config *cfg = manager->cfg;
    int i;

    if (READ_ONCE(manager->stopping))
        return;

    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        struct mwan_l2_flow_bucket *bucket = &manager->tx[i];
        struct mwan_l2_tx_flow *flow;

        spin_lock_bh(&bucket->lock);
        hlist_for_each_entry(flow, &bucket->head, node) {
            if (READ_ONCE(flow->backlog.qlen))
                mwan_multicore_tx_refill(cfg, flow);
        }
        spin_unlock_bh(&bucket->lock);
    }

    if (!READ_ONCE(manager->stopping) &&
        atomic64_read(&manager->tx_backlog_packets))
        schedule_delayed_work(&manager->tx_dispatch_work,
                              MWAN_L2_TX_BACKLOG_RETRY);
}

static void mwan_l2_flow_gc_workfn(struct work_struct *work)
{
    struct mwan_l2_flow_manager *manager =
        container_of(to_delayed_work(work), struct mwan_l2_flow_manager,
                     gc_work);
    struct mwan_config *cfg = manager->cfg;
    int i;

    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        struct mwan_l2_flow_bucket *bucket = &manager->tx[i];
        struct mwan_l2_tx_flow *flow;
        struct hlist_node *tmp;

        spin_lock_bh(&bucket->lock);
        hlist_for_each_entry_safe(flow, tmp, &bucket->head, node) {
            bool expired;

            spin_lock(&flow->submit_lock);
            if (mwan_l2_tx_flow_idle(flow) &&
                mwan_l2_tx_balance_inactive(flow)) {
                mwan_l2_tx_balance_deactivate(cfg, flow);
                if (mwan_l2_tx_worker_inactive(flow))
                    mwan_l2_tx_worker_deactivate(cfg, flow);
            }
            expired = mwan_l2_tx_flow_idle(flow) &&
                      mwan_l2_flow_expired(READ_ONCE(flow->last_seen),
                                           READ_ONCE(flow->closing));
            spin_unlock(&flow->submit_lock);
            if (!expired)
                continue;
            hlist_del_init(&flow->node);
            atomic_dec(&manager->tx_count);
            atomic64_inc(&manager->tx_expired);
            mwan_l2_tx_worker_deactivate(cfg, flow);
            mwan_l2_tx_balance_deactivate(cfg, flow);
            mwan_l2_tx_flow_put(flow);
        }
        spin_unlock_bh(&bucket->lock);
    }

    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        struct mwan_l2_flow_bucket *bucket = &manager->rx[i];
        struct mwan_l2_rx_flow *victim;

        do {
            struct mwan_l2_rx_flow *flow;
            bool empty;
            int slot;

            victim = NULL;
            spin_lock_bh(&bucket->lock);
            hlist_for_each_entry(flow, &bucket->head, node) {
                if (atomic_read(&flow->pending_crypto) ||
                    !mwan_l2_flow_expired(READ_ONCE(flow->last_seen),
                                          READ_ONCE(flow->closing)))
                    continue;
                empty = true;
                spin_lock(&flow->reorder_lock);
                for (slot = 0; slot < MWAN_FLOW_RING_SIZE; slot++) {
                    if (flow->ring[slot]) {
                        empty = false;
                        break;
                    }
                }
                if (empty) {
                    WRITE_ONCE(flow->stopping, true);
                    hlist_del_init(&flow->node);
                    victim = flow;
                }
                spin_unlock(&flow->reorder_lock);
                if (victim)
                    break;
            }
            spin_unlock_bh(&bucket->lock);

            if (!victim)
                break;
            atomic_dec(&manager->rx_count);
            atomic64_inc(&manager->rx_expired);
            if (victim->owner_worker >= 0 &&
                victim->owner_worker < cfg->num_workers)
                atomic64_dec(&cfg->l2_workers[victim->owner_worker]
                                               .assigned_flows);
            mwan_l2_timer_delete_sync(&victim->reorder_timer);
            mwan_l2_rx_flow_put(victim);
        } while (1);
    }

    if (!READ_ONCE(manager->stopping))
        schedule_delayed_work(&manager->gc_work, MWAN_FLOW_GC_INTERVAL);
}

void mwan_l2_flow_manager_start(struct mwan_config *cfg)
{
    if (!cfg || !cfg->l2_workers)
        return;
    schedule_delayed_work(&cfg->flows.gc_work, MWAN_FLOW_GC_INTERVAL);
}

static void mwan_l2_free_rx_ring(struct mwan_l2_rx_flow *flow)
{
    u32 expected_slot;
    int i;

    spin_lock_bh(&flow->reorder_lock);
    expected_slot = flow->expected_seq & MWAN_FLOW_RING_MASK;
    for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
        if (flow->ring[i]) {
            u32 offset = ((u32)i - expected_slot) &
                         MWAN_FLOW_RING_MASK;

            mwan_reorder_drop_trace(MWAN_DROP_RX_REORDER_CLEANUP, flow,
                                    flow->ring[i],
                                    flow->expected_seq + offset,
                                    0, 0, -ESHUTDOWN);
            kfree_skb(flow->ring[i]);
            flow->ring[i] = NULL;
            flow->slot_seq[i] = 0;
            flow->slot_time[i] = 0;
        }
    }
    flow->reorder_queued = 0;
    spin_unlock_bh(&flow->reorder_lock);
}

void mwan_l2_flow_manager_stop(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return;
    WRITE_ONCE(cfg->flows.stopping, true);
    cancel_delayed_work_sync(&cfg->flows.tx_dispatch_work);
    cancel_delayed_work_sync(&cfg->flows.gc_work);
    mwan_l2_tx_emit_stop(cfg);

    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        struct mwan_l2_tx_flow *tx;
        struct mwan_l2_rx_flow *rx;
        struct hlist_node *tmp;

        spin_lock_bh(&cfg->flows.tx[i].lock);
        hlist_for_each_entry_safe(tx, tmp, &cfg->flows.tx[i].head, node) {
            hlist_del_init(&tx->node);
            mwan_multicore_tx_backlog_purge(cfg, tx);
            mwan_l2_tx_balance_deactivate(cfg, tx);
            mwan_l2_tx_worker_deactivate(cfg, tx);
            mwan_l2_tx_flow_put(tx);
        }
        spin_unlock_bh(&cfg->flows.tx[i].lock);

        spin_lock_bh(&cfg->flows.rx[i].lock);
        hlist_for_each_entry_safe(rx, tmp, &cfg->flows.rx[i].head, node) {
            WRITE_ONCE(rx->stopping, true);
            hlist_del_init(&rx->node);
            spin_unlock_bh(&cfg->flows.rx[i].lock);
            mwan_l2_timer_delete_sync(&rx->reorder_timer);
            mwan_l2_free_rx_ring(rx);
            mwan_l2_rx_flow_put(rx);
            spin_lock_bh(&cfg->flows.rx[i].lock);
        }
        spin_unlock_bh(&cfg->flows.rx[i].lock);
    }
}

struct mwan_l2_tx_flow *
mwan_l2_tx_flow_get(struct mwan_config *cfg,
                    const struct mwan_l2_flow_key *key, u32 flow_hash,
                    bool control_packet, int requested_tunnel_idx,
                    bool allow_tunnel_remap)
{
    struct mwan_l2_tx_flow *flow;
    struct mwan_l2_tx_flow *candidate;
    struct mwan_l2_flow_bucket *bucket;
    u32 index;
    int owner;
    int tunnel_idx;
    u16 admission_active_count = 0;
    u16 admission_configured_count = 0;

    if (!cfg || !key || READ_ONCE(cfg->flows.stopping))
        return NULL;
    index = mwan_l2_tx_bucket(key);
    bucket = &cfg->flows.tx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (mwan_l2_flow_key_equal(&flow->key, key)) {
            spin_lock(&flow->submit_lock);
            if (allow_tunnel_remap &&
                !READ_ONCE(flow->closing) &&
                mwan_l2_tx_flow_idle(flow) &&
                mwan_l2_tx_worker_inactive(flow)) {
                mwan_l2_tx_balance_deactivate(cfg, flow);
                mwan_l2_tx_worker_deactivate(cfg, flow);
            }
            if (!mwan_l2_tx_worker_reactivate(cfg, flow, flow_hash,
                                              control_packet)) {
                spin_unlock(&flow->submit_lock);
                spin_unlock_bh(&bucket->lock);
                return NULL;
            }
            if (allow_tunnel_remap &&
                !mwan_tunnel_balance_is_usable(cfg, flow->tunnel_idx)) {
                bool old_counted =
                    atomic_read(&flow->balance_counted) != 0;

                tunnel_idx = mwan_tunnel_balance_reassign_flow(
                    cfg, flow->tunnel_idx, flow_hash, old_counted);
                if (tunnel_idx >= 0) {
                    WRITE_ONCE(flow->tunnel_idx, (u16)tunnel_idx);
                    atomic_set(&flow->balance_counted, 1);
                }
            } else if (allow_tunnel_remap &&
                       READ_ONCE(flow->tunnel_idx) !=
                           READ_ONCE(flow->home_tunnel_idx) &&
                       mwan_l2_tx_flow_idle(flow) &&
                       refcount_read(&flow->refs) == 1 &&
                       mwan_tunnel_balance_is_active(
                           cfg, READ_ONCE(flow->home_tunnel_idx))) {
                u16 old_tunnel_idx = READ_ONCE(flow->tunnel_idx);
                u16 home_tunnel_idx = READ_ONCE(flow->home_tunnel_idx);
                bool old_counted =
                    atomic_read(&flow->balance_counted) != 0;

                /* The single remaining reference belongs to the flow table;
                 * together with pending_crypto == 0 this proves that no
                 * packet is queued, in flight, or already preselected on the
                 * old path. Preserve the sticky worker, token and sequence. */
                tunnel_idx = mwan_tunnel_balance_move_flow(
                    cfg, old_tunnel_idx, home_tunnel_idx, old_counted);
                if (!tunnel_idx) {
                    WRITE_ONCE(flow->tunnel_idx, home_tunnel_idx);
                    atomic_set(&flow->balance_counted, 1);
                }
            } else if (allow_tunnel_remap &&
                       READ_ONCE(flow->tunnel_idx) ==
                           READ_ONCE(flow->home_tunnel_idx) &&
                       READ_ONCE(flow->rebalance_on_recovery) &&
                       !READ_ONCE(flow->closing) &&
                       mwan_l2_tx_flow_idle(flow) &&
                       refcount_read(&flow->refs) == 1) {
                u16 old_tunnel_idx = READ_ONCE(flow->tunnel_idx);
                u16 active_count = 0;
                u16 configured_count = 0;
                bool old_counted =
                    atomic_read(&flow->balance_counted) != 0;

                tunnel_idx = mwan_tunnel_balance_recover_flow(
                    cfg, old_tunnel_idx, flow_hash, old_counted,
                    READ_ONCE(flow->admission_active_count),
                    &active_count, &configured_count);
                if (tunnel_idx >= 0) {
                    WRITE_ONCE(flow->tunnel_idx, (u16)tunnel_idx);
                    WRITE_ONCE(flow->home_tunnel_idx, (u16)tunnel_idx);
                    WRITE_ONCE(flow->admission_active_count,
                               active_count);
                    WRITE_ONCE(flow->rebalance_on_recovery,
                               active_count < configured_count);
                    atomic_set(&flow->balance_counted, 1);
                    atomic64_inc(&cfg->flows.tx_recovery_updated);
                    if (tunnel_idx != old_tunnel_idx)
                        atomic64_inc(&cfg->flows.tx_recovery_moved);
                }
            }
            if (allow_tunnel_remap && !READ_ONCE(flow->closing) &&
                mwan_tunnel_balance_is_active(
                    cfg, READ_ONCE(flow->tunnel_idx)) &&
                atomic_cmpxchg(&flow->balance_counted, 0, 1) == 0) {
                mwan_tunnel_balance_activate_flow(cfg,
                                                   flow->tunnel_idx);
            }
            refcount_inc(&flow->refs);
            WRITE_ONCE(flow->last_seen, jiffies);
            spin_unlock(&flow->submit_lock);
            spin_unlock_bh(&bucket->lock);
            return flow;
        }
    }
    spin_unlock_bh(&bucket->lock);

    if (atomic_read(&cfg->flows.tx_count) >= MWAN_FLOW_MAX_ACTIVE) {
        atomic64_inc(&cfg->flows.table_full);
        return NULL;
    }
    candidate = kzalloc(sizeof(*candidate), GFP_ATOMIC);
    if (!candidate)
        return NULL;
    candidate->streams = kcalloc(cfg->num_tunnels,
                                 sizeof(*candidate->streams), GFP_ATOMIC);
    if (!candidate->streams) {
        kfree(candidate);
        return NULL;
    }
    candidate->manager = &cfg->flows;
    candidate->num_streams = cfg->num_tunnels;
    owner = mwan_l2_select_tx_worker(cfg, flow_hash, -1, control_packet);
    if (owner < 0) {
        mwan_l2_tx_flow_free(candidate);
        return NULL;
    }
    if (requested_tunnel_idx >= 0) {
        if (requested_tunnel_idx >= cfg->num_tunnels) {
            atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
            mwan_l2_tx_flow_free(candidate);
            return NULL;
        }
        /* Exact-path callers are control probes (notably BFD). Data flows
         * are created by mwan_l2_tx_flow_select_tunnel() before encap and
         * therefore already exist when the worker submit path gets here. */
        tunnel_idx = requested_tunnel_idx;
    } else {
        tunnel_idx = mwan_tunnel_balance_assign_flow(
            cfg, flow_hash, &admission_active_count,
            &admission_configured_count);
    }
    if (tunnel_idx < 0) {
        atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
        mwan_l2_tx_flow_free(candidate);
        return NULL;
    }
    candidate->key = *key;
    candidate->flow_token = mwan_l2_new_flow_token();
    candidate->flow_id = flow_hash;
    refcount_set(&candidate->refs, 1); /* table reference */
    atomic_set(&candidate->next_seq, 0);
    atomic_set(&candidate->pending_crypto, 0);
    atomic_set(&candidate->balance_counted,
               requested_tunnel_idx < 0 ? 1 : 0);
    atomic_set(&candidate->worker_counted, 1);
    atomic_set(&candidate->exec_mode, MWAN_FLOW_EXEC_LEGACY);
    candidate->pipeline_worker = -1;
    spin_lock_init(&candidate->submit_lock);
    skb_queue_head_init(&candidate->backlog);
    candidate->backlog_bytes = 0;
    candidate->owner_worker = owner;
    candidate->pp_lane = -1;
    candidate->pp_lane_left = 0;
    candidate->home_tunnel_idx = (u16)tunnel_idx;
    candidate->tunnel_idx = (u16)tunnel_idx;
    candidate->admission_active_count = admission_active_count;
    candidate->rebalance_on_recovery =
        requested_tunnel_idx < 0 &&
        admission_active_count < admission_configured_count;
    candidate->last_seen = jiffies;
    INIT_HLIST_NODE(&candidate->node);

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (mwan_l2_flow_key_equal(&flow->key, key)) {
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
            if (atomic_read(&candidate->balance_counted))
                mwan_tunnel_balance_release_flow(
                    cfg, candidate->tunnel_idx);
            mwan_l2_tx_flow_free(candidate);
            return flow;
        }
    }
    hlist_add_head(&candidate->node, &bucket->head);
    atomic_inc(&cfg->flows.tx_count);
    atomic64_inc(&cfg->flows.tx_created);
    if (candidate->key.type == MWAN_FLOW_KEY_ESP_SA ||
        candidate->key.type == MWAN_FLOW_KEY_ESP_NATT_SA)
        atomic64_inc(&cfg->flows.tx_ipsec_sa_created);
    else if (candidate->key.type == MWAN_FLOW_KEY_IPSEC_FRAGMENT)
        atomic64_inc(&cfg->flows.tx_ipsec_fragment_created);
    if (candidate->rebalance_on_recovery)
        atomic64_inc(&cfg->flows.tx_degraded_admitted);
    refcount_inc(&candidate->refs); /* caller reference */
    spin_unlock_bh(&bucket->lock);
    return candidate;
}

int mwan_l2_tx_flow_select_tunnel(struct mwan_config *cfg,
                                  const struct mwan_l2_flow_key *key,
                                  u32 flow_hash, bool control_packet,
                                  u16 *tunnel_idx,
                                  struct mwan_l2_tx_flow **flow_out)
{
    struct mwan_l2_tx_flow *flow;
    u16 selected;

    if (!cfg || !key || !tunnel_idx || !flow_out)
        return -EINVAL;
    *flow_out = NULL;
    flow = mwan_l2_tx_flow_get(cfg, key, flow_hash, control_packet, -1,
                               true);
    if (!flow)
        return -ENOSPC;
    selected = READ_ONCE(flow->tunnel_idx);
    if (!mwan_tunnel_balance_is_usable(cfg, selected)) {
        mwan_l2_tx_flow_put(flow);
        return -ENETDOWN;
    }
    *tunnel_idx = selected;
    *flow_out = flow;
    return 0;
}

struct mwan_l2_tx_flow *
mwan_l2_tx_flow_hold(struct mwan_l2_tx_flow *flow)
{
    if (!flow || !refcount_inc_not_zero(&flow->refs))
        return NULL;
    return flow;
}

void mwan_l2_tx_flow_put(struct mwan_l2_tx_flow *flow)
{
    if (flow && refcount_dec_and_test(&flow->refs))
        mwan_l2_tx_flow_free(flow);
}

bool mwan_l2_tx_flow_release_queued(struct mwan_config *cfg,
                                   const struct mwan_l2_flow_key *key,
                                   int owner_worker)
{
    struct mwan_l2_flow_bucket *bucket;
    struct mwan_l2_tx_flow *flow;
    u32 index;
    bool released = false;

    if (!cfg || !key || owner_worker < 0 ||
        owner_worker >= cfg->num_workers)
        return false;
    index = mwan_l2_tx_bucket(key);
    bucket = &cfg->flows.tx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        /* A single flow can now have packets queued on several crypto lanes;
         * the full key, not the home worker, identifies the reference. */
        if (!mwan_l2_flow_key_equal(&flow->key, key))
            continue;
        if (atomic_add_unless(&flow->pending_crypto, -1, 0)) {
            /* The table reference keeps flow alive while bucket->lock is
             * held; this put releases exactly one queue-owned reference. */
            mwan_l2_tx_flow_put(flow);
            released = true;
        }
        break;
    }
    spin_unlock_bh(&bucket->lock);
    return released;
}

void mwan_l2_tx_flow_touch(struct mwan_l2_tx_flow *flow, bool closing)
{
    if (!flow)
        return;
    WRITE_ONCE(flow->last_seen, jiffies);
    if (closing)
        WRITE_ONCE(flow->closing, true);
}

void mwan_l2_tx_flow_complete(struct mwan_config *cfg,
                              struct mwan_l2_tx_flow *flow)
{
    bool idle;

    if (!cfg || !flow)
        return;
    spin_lock_bh(&flow->submit_lock);
    idle = atomic_dec_return(&flow->pending_crypto) == 0 &&
           skb_queue_empty(&flow->backlog);
    spin_unlock_bh(&flow->submit_lock);
    if (idle && READ_ONCE(flow->closing))
        mwan_l2_tx_balance_deactivate(cfg, flow);
}

static void mwan_l2_tx_flow_complete_count(struct mwan_config *cfg,
                                           struct mwan_l2_tx_flow *flow,
                                           unsigned int count)
{
    bool idle;
    int pending;

    if (!cfg || !flow || !count)
        return;
    spin_lock_bh(&flow->submit_lock);
    pending = atomic_sub_return(count, &flow->pending_crypto);
    WARN_ON_ONCE(pending < 0);
    idle = pending == 0 && skb_queue_empty(&flow->backlog);
    spin_unlock_bh(&flow->submit_lock);
    if (idle && READ_ONCE(flow->closing))
        mwan_l2_tx_balance_deactivate(cfg, flow);
}

int mwan_l2_tx_flow_prepare_stream(struct mwan_config *cfg,
                                   struct mwan_l2_tx_flow *flow,
                                   u16 tunnel_idx)
{
    struct mwan_l2_tx_stream *stream;
    unsigned int window;
    unsigned int ring_size;
    int emitter_worker;
    int emitter_pipeline;

    if (!cfg || !flow || tunnel_idx >= flow->num_streams)
        return -EINVAL;
    if (flow->streams[tunnel_idx])
        return 0;

    window = max_t(unsigned int, 8U, cfg->num_workers * 4U);
    window = min_t(unsigned int, window, MWAN_FLOW_RING_SIZE - 1U);
    ring_size = roundup_pow_of_two(window);
    emitter_worker = mwan_l2_select_tx_emitter(cfg, flow->flow_id,
                                                tunnel_idx);
    if (emitter_worker < 0)
        return emitter_worker;
    emitter_pipeline = mwan_l2_select_tx_emit_pipeline(cfg, flow,
                                                        tunnel_idx);
    stream = kzalloc(struct_size(stream, slots, ring_size), GFP_ATOMIC);
    if (!stream)
        return -ENOMEM;
    stream->flow = flow;
    stream->tunnel_idx = tunnel_idx;
    stream->ring_size = ring_size;
    stream->ring_mask = ring_size - 1U;
    stream->emit_seq = 1;
    stream->emitter_worker = emitter_worker;
    stream->emitter_pipeline = emitter_pipeline;
    spin_lock_init(&stream->lock);
    INIT_WORK(&stream->emit_work, mwan_l2_tx_emit_workfn);
    flow->streams[tunnel_idx] = stream;
    return 0;
}

u32 mwan_l2_tx_flow_next_emit_seq(struct mwan_l2_tx_flow *flow,
                                  u16 tunnel_idx)
{
    struct mwan_l2_tx_stream *stream;

    if (WARN_ON_ONCE(!flow || tunnel_idx >= flow->num_streams))
        return 0;
    stream = flow->streams[tunnel_idx];
    if (WARN_ON_ONCE(!stream))
        return 0;
    return ++stream->next_emit_seq;
}

static int mwan_l2_tx_stream_emit_cpu(const struct mwan_config *cfg,
                                      const struct mwan_l2_tx_stream *stream)
{
    if (stream->emitter_pipeline >= 0 &&
        stream->emitter_pipeline < cfg->num_pipeline_workers &&
        cfg->pipeline_workers)
        return cfg->pipeline_workers[stream->emitter_pipeline].cpu;
    return cfg->l2_workers[stream->emitter_worker].cpu;
}

/* Publish one completed TX crypto operation into its flow commit ring.  The
 * caller transfers both the skb (when non-NULL) and exactly one flow
 * reference.  A NULL skb is a tombstone for a failed crypto operation, so a
 * later packet can never wait forever behind a known failure. */
void mwan_l2_tx_flow_publish(struct mwan_config *cfg,
                             struct mwan_l2_tx_flow *flow,
                             struct sk_buff *skb, u16 tunnel_idx,
                             u32 emit_seq)
{
    struct mwan_l2_tx_stream *stream;
    struct workqueue_struct *emit_wq;
    bool schedule = false;
    u32 delta;
    u32 slot;

    if (unlikely(!cfg || !flow)) {
        kfree_skb(skb);
        if (flow) {
            mwan_l2_tx_flow_complete(cfg, flow);
            mwan_l2_tx_flow_put(flow);
        }
        return;
    }

    if (unlikely(tunnel_idx >= flow->num_streams ||
                 !(stream = READ_ONCE(flow->streams[tunnel_idx])))) {
        WARN_ON_ONCE(1);
        kfree_skb(skb);
        mwan_l2_tx_flow_complete(cfg, flow);
        mwan_l2_tx_flow_put(flow);
        return;
    }

    spin_lock_bh(&stream->lock);
    if (unlikely((s32)(emit_seq - stream->emit_seq) < 0)) {
        spin_unlock_bh(&stream->lock);
        kfree_skb(skb);
        mwan_l2_tx_flow_complete(cfg, flow);
        mwan_l2_tx_flow_put(flow);
        return;
    }
    delta = emit_seq - stream->emit_seq;
    if (unlikely(delta >= stream->ring_size)) {
        /* The execution window is capped below the ring size, so reaching
         * this branch indicates broken accounting rather than congestion. */
        spin_unlock_bh(&stream->lock);
        WARN_ON_ONCE(1);
        kfree_skb(skb);
        mwan_l2_tx_flow_complete(cfg, flow);
        mwan_l2_tx_flow_put(flow);
        return;
    }

    slot = emit_seq & stream->ring_mask;
    if (unlikely(stream->slots[slot].ready)) {
        spin_unlock_bh(&stream->lock);
        WARN_ON_ONCE(1);
        kfree_skb(skb);
        mwan_l2_tx_flow_complete(cfg, flow);
        mwan_l2_tx_flow_put(flow);
        return;
    }
    stream->slots[slot].skb = skb;
    stream->slots[slot].emit_seq = emit_seq;
    stream->slots[slot].ready = true;
    if (!stream->emitting) {
        stream->emitting = true;
        /* Slot references are released one by one below.  Keep a separate
         * drain reference so GC cannot free the flow after the final pending
         * operation reaches zero but before the emitter exits its loop. */
        refcount_inc(&flow->refs);
        schedule = true;
    }
    spin_unlock_bh(&stream->lock);

    if (!schedule)
        return;
    emit_wq = READ_ONCE(cfg->flows.tx_emit_wq);
    if (likely(emit_wq) &&
        queue_work_on(mwan_l2_tx_stream_emit_cpu(cfg, stream),
                      emit_wq, &stream->emit_work))
        return;

    atomic64_inc(&cfg->flows.tx_emit_schedule_collisions);
    if (work_busy(&stream->emit_work)) {
        mwan_l2_tx_flow_put(flow); /* redundant emitter reference */
        return;
    }
    if (emit_wq && queue_work(emit_wq, &stream->emit_work))
        return;
    if (work_busy(&stream->emit_work)) {
        mwan_l2_tx_flow_put(flow); /* work raced with the fallback */
        return;
    }
    /* This is reachable only during teardown after producers should already
     * be stopped. Drain synchronously so no committed slot is stranded. */
    mwan_l2_tx_emit_workfn(&stream->emit_work);
}

static void mwan_l2_tx_emit_workfn(struct work_struct *work)
{
    struct mwan_l2_tx_stream *stream =
        container_of(work, struct mwan_l2_tx_stream, emit_work);
    struct mwan_l2_tx_flow *flow = stream->flow;
    struct mwan_l2_flow_manager *manager = flow->manager;
    struct mwan_config *cfg = manager->cfg;
    struct mwan_l2_worker *worker = NULL;
    struct mwan_pipeline_worker *pipeline = NULL;
    atomic64_t *role_emit_ns = NULL;
    atomic64_t *role_emit_packets = NULL;
    unsigned int budget = MWAN_L2_TX_EMIT_BUDGET;
    bool requeued = false;

    /* An emitter on the output-role pool is accounted there, so crypto lane
     * selection no longer treats its CPU as emit-busy. */
    if (stream->emitter_pipeline >= 0 &&
        stream->emitter_pipeline < cfg->num_pipeline_workers &&
        cfg->pipeline_workers)
        pipeline = &cfg->pipeline_workers[stream->emitter_pipeline];
    else if (stream->emitter_worker >= 0 &&
             stream->emitter_worker < cfg->num_workers)
        worker = &cfg->l2_workers[stream->emitter_worker];
    if (pipeline) {
        atomic_inc(&pipeline->tx_emit_busy);
        role_emit_ns = &pipeline->role_emit_ns;
        role_emit_packets = &pipeline->role_emit_packets;
    } else if (worker) {
        atomic_inc(&worker->tx_emit_busy);
        role_emit_ns = &worker->role_emit_ns;
        role_emit_packets = &worker->role_emit_packets;
    }

    for (;;) {
        struct sk_buff *batch[MWAN_L2_TX_EMIT_BATCH];
        unsigned int count = 0;
        unsigned int packets = 0;
        unsigned int tombstones = 0;
        unsigned int i;
        u64 role_start;

        local_bh_disable();
        role_start = mwan_role_clock();
        spin_lock(&stream->lock);
        while (count < ARRAY_SIZE(batch)) {
            u32 slot = stream->emit_seq & stream->ring_mask;
            struct mwan_l2_tx_emit_slot *entry = &stream->slots[slot];

            if (!entry->ready || entry->emit_seq != stream->emit_seq)
                break;
            batch[count++] = entry->skb;
            entry->skb = NULL;
            entry->emit_seq = 0;
            entry->ready = false;
            stream->emit_seq++;
        }
        if (!count) {
            stream->emitting = false;
            spin_unlock(&stream->lock);
            local_bh_enable();
            break;
        }
        spin_unlock(&stream->lock);

        for (i = 0; i < count; i++) {
            if (batch[i]) {
                int ret = dev_queue_xmit(batch[i]);

                packets++;
                if (net_xmit_eval(ret))
                    atomic64_inc(&manager->tx_emit_xmit_failures);
            } else {
                tombstones++;
            }
        }
        if (role_emit_ns) {
            mwan_role_charge(role_emit_ns, &role_start);
            atomic64_add(packets, role_emit_packets);
        }
        local_bh_enable();

        atomic64_inc(&manager->tx_emit_batches);
        atomic64_add(packets, &manager->tx_emit_packets);
        atomic64_add(tombstones, &manager->tx_emit_tombstones);
        mwan_l2_atomic64_update_max(&manager->tx_emit_max_batch, count);
        mwan_l2_tx_flow_complete_count(cfg, flow, count);
        for (i = 0; i < count; i++)
            mwan_l2_tx_flow_put(flow); /* slot reference */
        if (mwan_multicore_tx_refill(cfg, flow))
            mwan_multicore_tx_backlog_kick(cfg);
        cond_resched();
        if (!--budget) {
            struct workqueue_struct *emit_wq =
                READ_ONCE(cfg->flows.tx_emit_wq);

            /* Yield the emit CPU to other streams queued behind this run.
             * emitting stays true, so producers do not schedule a second
             * run, and the drain reference moves to the requeued run. */
            if (emit_wq &&
                queue_work_on(mwan_l2_tx_stream_emit_cpu(cfg, stream),
                              emit_wq, &stream->emit_work)) {
                requeued = true;
                break;
            }
            budget = MWAN_L2_TX_EMIT_BUDGET;
        }
    }

    if (pipeline)
        atomic_dec(&pipeline->tx_emit_busy);
    else if (worker)
        atomic_dec(&worker->tx_emit_busy);
    if (!requeued)
        mwan_l2_tx_flow_put(flow); /* emitter reference */
}

u32 mwan_l2_tx_flow_next_seq(struct mwan_l2_tx_flow *flow)
{
    return (u32)atomic_inc_return(&flow->next_seq);
}

struct mwan_l2_rx_flow *
mwan_l2_rx_flow_lookup(struct mwan_config *cfg, u64 flow_token)
{
    struct mwan_l2_rx_flow *flow;
    struct mwan_l2_flow_bucket *bucket;
    u32 index;

    flow_token &= MWAN_FLOW_COOKIE_MASK;
    if (!cfg || !flow_token || READ_ONCE(cfg->flows.stopping))
        return NULL;
    index = mwan_l2_rx_bucket(flow_token);
    bucket = &cfg->flows.rx[index];
    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token == flow_token) {
            /* Reserve in-flight lifetime under the same lock used by GC.
             * This is not activity: last_seen remains unchanged until AEAD
             * succeeds in the worker. */
            atomic_inc(&flow->pending_crypto);
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            return flow;
        }
    }
    spin_unlock_bh(&bucket->lock);

    return NULL;
}

/* This is the only RX flow-creation entry point.  Callers must invoke it only
 * after the packet header and ciphertext have passed AEAD authentication.
 * Worker admission also happens here, after authentication.  The temporary
 * candidate worker is only responsible for verifying unknown tokens; normal
 * packets retain the existing load-aware sticky-owner model. */
struct mwan_l2_rx_flow *
mwan_l2_rx_flow_get_authenticated(struct mwan_config *cfg, u64 flow_token,
                                  u32 first_seq)
{
    struct mwan_l2_rx_flow *flow;
    struct mwan_l2_rx_flow *candidate;
    struct mwan_l2_flow_bucket *bucket;
    u32 index;
    int owner;

    flow_token &= MWAN_FLOW_COOKIE_MASK;
    if (!cfg || !flow_token || READ_ONCE(cfg->flows.stopping) ||
        !cfg->l2_workers)
        return NULL;
    index = mwan_l2_rx_bucket(flow_token);
    bucket = &cfg->flows.rx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token == flow_token) {
            atomic_inc(&flow->pending_crypto);
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            return flow;
        }
    }
    spin_unlock_bh(&bucket->lock);

    candidate = kzalloc(sizeof(*candidate), GFP_KERNEL);
    if (!candidate)
        return NULL;
    owner = mwan_l2_select_rx_worker(cfg, lower_32_bits(flow_token), -1,
                                     true);
    if (owner < 0) {
        kfree(candidate);
        return NULL;
    }
    candidate->flow_token = flow_token;
    refcount_set(&candidate->refs, 1); /* table reference */
    candidate->expected_seq = first_seq;
    atomic_set(&candidate->pending_crypto, 1);
    candidate->owner_worker = owner;
    atomic_set(&candidate->exec_mode, MWAN_FLOW_EXEC_LEGACY);
    candidate->pipeline_worker = -1;
    candidate->last_seen = jiffies;
    candidate->manager = &cfg->flows;
    spin_lock_init(&candidate->reorder_lock);
    timer_setup(&candidate->reorder_timer, mwan_l2_rx_reorder_timeout, 0);
    INIT_HLIST_NODE(&candidate->node);

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token == flow_token) {
            atomic_inc(&flow->pending_crypto);
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            atomic64_dec(&cfg->l2_workers[owner].assigned_flows);
            kfree(candidate);
            return flow;
        }
    }
    if (!atomic_add_unless(&cfg->flows.rx_count, 1,
                           MWAN_FLOW_MAX_ACTIVE)) {
        spin_unlock_bh(&bucket->lock);
        atomic64_inc(&cfg->flows.table_full);
        atomic64_dec(&cfg->l2_workers[owner].assigned_flows);
        kfree(candidate);
        return NULL;
    }
    hlist_add_head(&candidate->node, &bucket->head);
    atomic64_inc(&cfg->flows.rx_created);
    refcount_inc(&candidate->refs); /* caller reference */
    spin_unlock_bh(&bucket->lock);
    return candidate;
}

void mwan_l2_rx_flow_put(struct mwan_l2_rx_flow *flow)
{
    if (flow && refcount_dec_and_test(&flow->refs))
        kfree(flow);
}

bool mwan_l2_rx_flow_release_queued(struct mwan_config *cfg, u64 flow_token,
                                   int owner_worker)
{
    struct mwan_l2_flow_bucket *bucket;
    struct mwan_l2_rx_flow *flow;
    u32 index;
    bool released = false;

    flow_token &= MWAN_FLOW_COOKIE_MASK;
    if (!cfg || !flow_token || owner_worker < 0 ||
        owner_worker >= cfg->num_workers)
        return false;
    index = mwan_l2_rx_bucket(flow_token);
    bucket = &cfg->flows.rx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        /* flow_token is globally unique for the configuration.  Packets of
         * this flow may be queued on any crypto worker. */
        if (flow->flow_token != flow_token)
            continue;
        if (atomic_add_unless(&flow->pending_crypto, -1, 0)) {
            mwan_l2_rx_flow_put(flow);
            released = true;
        }
        break;
    }
    spin_unlock_bh(&bucket->lock);
    return released;
}

void mwan_l2_rx_flow_touch(struct mwan_l2_rx_flow *flow, bool closing)
{
    if (!flow)
        return;
    WRITE_ONCE(flow->last_seen, jiffies);
    if (closing)
        WRITE_ONCE(flow->closing, true);
}

/* Called with reorder_lock held. Places one authenticated packet in the
 * reorder ring and moves every packet that is now in order onto @batch.
 * Late and duplicate packets are traced and freed here. */
static void mwan_l2_rx_flow_insert_locked(struct mwan_l2_rx_flow *flow,
                                          struct sk_buff *skb, u32 flow_seq,
                                          struct sk_buff_head *batch)
{
    u32 delta;
    u32 slot;

    if (unlikely((s32)(flow_seq - flow->expected_seq) < 0)) {
        atomic64_inc(&flow->manager->reorder_late);
        mwan_rekey_diag_count_drop(flow->manager->cfg,
                                   MWAN_REKEY_DROP_REORDER_LATE, 0);
        mwan_reorder_drop_trace(MWAN_DROP_REORDER_LATE, flow, skb,
                                flow_seq, 0, 0, -ERANGE);
        kfree_skb(skb);
        return;
    }
    delta = (u32)(flow_seq - flow->expected_seq);
    if (unlikely(delta >= MWAN_FLOW_RING_SIZE)) {
        u32 advance = delta - (MWAN_FLOW_RING_SIZE - 1);
        u32 old_expected = flow->expected_seq;
        u32 inspect = min_t(u32, advance, MWAN_FLOW_RING_SIZE);
        u32 delivered = 0;
        u32 preserved = 0;
        int i;

        /* This function is reached only after AES-GCM authentication has
         * succeeded. Slide only far enough to include it. Buffered packets
         * that leave the window are emitted in sequence order; only sequence
         * numbers that are genuinely absent are skipped. */
        atomic64_inc(&flow->manager->reorder_too_far);
        atomic64_inc(&flow->manager->reorder_resync);
        for (i = 0; i < inspect; i++) {
            u32 seq = flow->expected_seq + i;
            u32 old_slot = seq & MWAN_FLOW_RING_MASK;
            struct sk_buff *old = flow->ring[old_slot];

            if (!old || flow->slot_seq[old_slot] != seq)
                continue;
            flow->ring[old_slot] = NULL;
            flow->slot_seq[old_slot] = 0;
            flow->slot_time[old_slot] = 0;
            flow->reorder_queued--;
            delivered++;
            mwan_l2_rx_batch_append(flow, batch, old);
        }
        atomic64_add((u64)advance - delivered,
                     &flow->manager->reorder_resync_skipped);
        flow->expected_seq += advance;
        for (i = 0; i < MWAN_FLOW_RING_SIZE; i++)
            if (flow->ring[i])
                preserved++;
        if (preserved)
            atomic64_add(preserved,
                         &flow->manager->reorder_resync_preserved);
        if (READ_ONCE(mwan_l2_diag_enabled)) {
            pr_warn_ratelimited("mwan_kmod: L2D REORDER_TOO_FAR token=%016llx expected=%u received=%u gap=%u flushed=0 window=%u\n",
                                flow->flow_token, old_expected, flow_seq,
                                delta, MWAN_FLOW_RING_SIZE);
            pr_warn_ratelimited("mwan_kmod: L2D REORDER_SLIDE token=%016llx advanced=%u delivered=%u preserved=%u new_expected=%u\n",
                                flow->flow_token, advance, delivered,
                                preserved, flow->expected_seq);
        }
    }

    slot = flow_seq & MWAN_FLOW_RING_MASK;
    if (unlikely(flow->ring[slot])) {
        if (flow->slot_seq[slot] == flow_seq) {
            atomic64_inc(&flow->manager->reorder_duplicate);
            mwan_reorder_drop_trace(MWAN_DROP_REORDER_DUPLICATE, flow, skb,
                                    flow_seq, 0, 0, -EEXIST);
            kfree_skb(skb);
            return;
        }
        /* Two distinct sequence numbers cannot occupy one slot while both
         * are inside the active receive window. Recover stale metadata without
         * sacrificing the newly authenticated packet. */
        WARN_ON_ONCE(1);
        mwan_reorder_drop_trace(MWAN_DROP_REORDER_EVICT, flow,
                                flow->ring[slot], flow->slot_seq[slot],
                                0, 0, -ENOBUFS);
        kfree_skb(flow->ring[slot]);
        flow->ring[slot] = NULL;
        flow->slot_seq[slot] = 0;
        flow->slot_time[slot] = 0;
        flow->reorder_queued--;
        atomic64_inc(&flow->manager->reorder_resync_flushed);
    }
    flow->ring[slot] = skb;
    flow->slot_seq[slot] = flow_seq;
    flow->slot_time[slot] = (u32)jiffies;
    flow->reorder_queued++;
    while (1) {
        u32 expected_slot = flow->expected_seq & MWAN_FLOW_RING_MASK;
        struct sk_buff *pending = flow->ring[expected_slot];

        if (!pending || flow->slot_seq[expected_slot] != flow->expected_seq)
            break;
        flow->ring[expected_slot] = NULL;
        flow->slot_seq[expected_slot] = 0;
        flow->slot_time[expected_slot] = 0;
        flow->reorder_queued--;
        flow->expected_seq++;
        mwan_l2_rx_batch_append(flow, batch, pending);
    }
}

/* Deliver a run of authenticated packets of one flow. The whole run is
 * inserted under a single reorder_lock acquisition, which keeps the ordered
 * section short when a crypto lane completes a burst of one flow. */
void mwan_l2_rx_flow_deliver_batch(struct mwan_l2_rx_flow *flow,
                                   struct sk_buff **skbs, const u32 *seqs,
                                   unsigned int count)
{
    struct sk_buff_head batch;
    unsigned int i;

    if (!count)
        return;
    if (!flow) {
        for (i = 0; i < count; i++) {
            if (!skbs[i])
                continue;
            mwan_reorder_drop_trace(MWAN_DROP_RX_FLOW_FAILED, flow, skbs[i],
                                    seqs[i], 0, 0, -EINVAL);
            kfree_skb(skbs[i]);
        }
        return;
    }

    __skb_queue_head_init(&batch);
    spin_lock_bh(&flow->reorder_lock);
    for (i = 0; i < count; i++)
        if (skbs[i])
            mwan_l2_rx_flow_insert_locked(flow, skbs[i], seqs[i], &batch);
    mwan_l2_reorder_arm_locked(flow);
    spin_unlock_bh(&flow->reorder_lock);

    if (!skb_queue_empty(&batch))
        mwan_l2_rx_reinject_batch(flow, &batch);
}

void mwan_l2_rx_flow_deliver(struct mwan_l2_rx_flow *flow,
                             struct sk_buff *skb, u32 flow_seq)
{
    if (!skb)
        return;
    mwan_l2_rx_flow_deliver_batch(flow, &skb, &flow_seq, 1);
}
