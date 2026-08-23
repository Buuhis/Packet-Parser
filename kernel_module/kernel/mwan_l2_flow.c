#include "mwan_state.h"

#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/version.h>

static void mwan_l2_flow_gc_workfn(struct work_struct *work);

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
    return hash_64(flow_token, ilog2(MWAN_FLOW_HASH_SIZE));
}

static bool mwan_l2_flow_key_equal(const struct mwan_l2_flow_key *a,
                                   const struct mwan_l2_flow_key *b)
{
    return !memcmp(a, b, sizeof(*a));
}

static u64 mwan_l2_new_flow_token(u8 key_id)
{
    u64 cookie;

    do {
        cookie = get_random_u64() & MWAN_FLOW_COOKIE_MASK;
    } while (!cookie);
    return ((u64)key_id << MWAN_FLOW_KEY_ID_SHIFT) | cookie;
}

static bool mwan_l2_flow_expired(unsigned long last_seen, bool closing)
{
    unsigned long timeout = closing ? MWAN_FLOW_CLOSING_TIMEOUT :
                                      MWAN_FLOW_IDLE_TIMEOUT;

    return time_after(jiffies, last_seen + timeout);
}

static void mwan_l2_rx_reorder_timeout(struct timer_list *timer)
{
    struct mwan_l2_rx_flow *flow =
        container_of(timer, struct mwan_l2_rx_flow, reorder_timer);
    bool restart = false;
    int i;

    spin_lock_bh(&flow->reorder_lock);
    while (1) {
        u32 slot = flow->expected_seq & MWAN_FLOW_RING_MASK;
        struct sk_buff *skb = flow->ring[slot];

        if (skb) {
            flow->ring[slot] = NULL;
            flow->slot_time[slot] = 0;
            flow->expected_seq++;
            netif_rx(skb);
            continue;
        }

        for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
            if (flow->ring[i] && flow->slot_time[i] &&
                time_after_eq(jiffies, flow->slot_time[i] +
                                        MWAN_REORDER_TIMEOUT))
                break;
        }
        if (i == MWAN_FLOW_RING_SIZE)
            break;
        flow->expected_seq++;
        atomic64_inc(&flow->manager->reorder_timeouts);
    }

    for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
        if (flow->ring[i]) {
            restart = true;
            break;
        }
    }
    if (restart && !READ_ONCE(flow->stopping))
        mod_timer(&flow->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
    spin_unlock_bh(&flow->reorder_lock);
}

int mwan_l2_flow_manager_init(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return -EINVAL;
    cfg->flows.cfg = cfg;
    cfg->flows.stopping = false;
    INIT_DELAYED_WORK(&cfg->flows.gc_work, mwan_l2_flow_gc_workfn);
    atomic_set(&cfg->flows.tx_count, 0);
    atomic_set(&cfg->flows.rx_count, 0);
    atomic64_set(&cfg->flows.tx_created, 0);
    atomic64_set(&cfg->flows.tx_expired, 0);
    atomic64_set(&cfg->flows.rx_created, 0);
    atomic64_set(&cfg->flows.rx_expired, 0);
    atomic64_set(&cfg->flows.table_full, 0);
    atomic64_set(&cfg->flows.reorder_late, 0);
    atomic64_set(&cfg->flows.reorder_duplicate, 0);
    atomic64_set(&cfg->flows.reorder_too_far, 0);
    atomic64_set(&cfg->flows.reorder_timeouts, 0);
    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&cfg->flows.tx[i].head);
        spin_lock_init(&cfg->flows.tx[i].lock);
        INIT_HLIST_HEAD(&cfg->flows.rx[i].head);
        spin_lock_init(&cfg->flows.rx[i].lock);
    }
    return 0;
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
            if (atomic_read(&flow->pending_crypto) ||
                !mwan_l2_flow_expired(READ_ONCE(flow->last_seen),
                                      READ_ONCE(flow->closing)))
                continue;
            hlist_del_init(&flow->node);
            atomic_dec(&manager->tx_count);
            atomic64_inc(&manager->tx_expired);
            if (flow->owner_worker >= 0 &&
                flow->owner_worker < cfg->num_workers)
                atomic64_dec(&cfg->l2_workers[flow->owner_worker]
                                               .tx_assigned_flows);
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
    int i;

    spin_lock_bh(&flow->reorder_lock);
    for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
        if (flow->ring[i]) {
            kfree_skb(flow->ring[i]);
            flow->ring[i] = NULL;
        }
    }
    spin_unlock_bh(&flow->reorder_lock);
}

void mwan_l2_flow_manager_stop(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return;
    WRITE_ONCE(cfg->flows.stopping, true);
    cancel_delayed_work_sync(&cfg->flows.gc_work);

    for (i = 0; i < MWAN_FLOW_HASH_SIZE; i++) {
        struct mwan_l2_tx_flow *tx;
        struct mwan_l2_rx_flow *rx;
        struct hlist_node *tmp;

        spin_lock_bh(&cfg->flows.tx[i].lock);
        hlist_for_each_entry_safe(tx, tmp, &cfg->flows.tx[i].head, node) {
            hlist_del_init(&tx->node);
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
                    bool control_packet)
{
    struct mwan_l2_tx_flow *flow;
    struct mwan_l2_tx_flow *candidate;
    struct mwan_l2_flow_bucket *bucket;
    u32 index;
    int owner;

    if (!cfg || !key || READ_ONCE(cfg->flows.stopping))
        return NULL;
    index = mwan_l2_tx_bucket(key);
    bucket = &cfg->flows.tx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (mwan_l2_flow_key_equal(&flow->key, key)) {
            refcount_inc(&flow->refs);
            WRITE_ONCE(flow->last_seen, jiffies);
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
    owner = mwan_l2_select_tx_worker(cfg, flow_hash, -1, control_packet);
    if (owner < 0) {
        kfree(candidate);
        return NULL;
    }
    candidate->key = *key;
    candidate->flow_token = mwan_l2_new_flow_token(cfg->key_id);
    refcount_set(&candidate->refs, 1); /* table reference */
    atomic_set(&candidate->next_seq, 0);
    atomic_set(&candidate->pending_crypto, 0);
    spin_lock_init(&candidate->submit_lock);
    candidate->owner_worker = owner;
    candidate->last_seen = jiffies;
    INIT_HLIST_NODE(&candidate->node);

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (mwan_l2_flow_key_equal(&flow->key, key)) {
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
            kfree(candidate);
            return flow;
        }
    }
    hlist_add_head(&candidate->node, &bucket->head);
    atomic_inc(&cfg->flows.tx_count);
    atomic64_inc(&cfg->flows.tx_created);
    refcount_inc(&candidate->refs); /* caller reference */
    spin_unlock_bh(&bucket->lock);
    return candidate;
}

void mwan_l2_tx_flow_put(struct mwan_l2_tx_flow *flow)
{
    if (flow && refcount_dec_and_test(&flow->refs))
        kfree(flow);
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
        if (!mwan_l2_flow_key_equal(&flow->key, key) ||
            flow->owner_worker != owner_worker)
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

u32 mwan_l2_tx_flow_next_seq(struct mwan_l2_tx_flow *flow)
{
    return (u32)atomic_inc_return(&flow->next_seq);
}

struct mwan_l2_rx_flow *
mwan_l2_rx_flow_get(struct mwan_config *cfg, u64 flow_token, u32 first_seq)
{
    struct mwan_l2_rx_flow *flow;
    struct mwan_l2_rx_flow *candidate;
    struct mwan_l2_flow_bucket *bucket;
    u32 index;
    int owner;

    if (!cfg || !flow_token || READ_ONCE(cfg->flows.stopping))
        return NULL;
    index = mwan_l2_rx_bucket(flow_token);
    bucket = &cfg->flows.rx[index];
    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token == flow_token) {
            refcount_inc(&flow->refs);
            WRITE_ONCE(flow->last_seen, jiffies);
            spin_unlock_bh(&bucket->lock);
            return flow;
        }
    }
    spin_unlock_bh(&bucket->lock);

    if (atomic_read(&cfg->flows.rx_count) >= MWAN_FLOW_MAX_ACTIVE) {
        atomic64_inc(&cfg->flows.table_full);
        return NULL;
    }
    candidate = kzalloc(sizeof(*candidate), GFP_ATOMIC);
    if (!candidate)
        return NULL;
    /* The encrypted RX prefix does not expose the inner protocol.  If every
     * CPU is admission-blocked, admit the first authenticated-flow candidate
     * on the CPU with the most remaining idle time.  TX can distinguish and
     * reserve this fallback for control packets; RX cannot do so safely before
     * decryption, and dropping the first ciphertext would also black-hole TCP
     * SYN/FIN/RST and pure ACK traffic. */
    owner = mwan_l2_select_rx_worker(cfg, lower_32_bits(flow_token), -1,
                                     true);
    if (owner < 0) {
        kfree(candidate);
        return NULL;
    }
    candidate->flow_token = flow_token;
    refcount_set(&candidate->refs, 1);
    candidate->expected_seq = first_seq;
    atomic_set(&candidate->pending_crypto, 0);
    candidate->owner_worker = owner;
    candidate->last_seen = jiffies;
    candidate->manager = &cfg->flows;
    spin_lock_init(&candidate->reorder_lock);
    timer_setup(&candidate->reorder_timer, mwan_l2_rx_reorder_timeout, 0);
    INIT_HLIST_NODE(&candidate->node);

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token == flow_token) {
            refcount_inc(&flow->refs);
            spin_unlock_bh(&bucket->lock);
            atomic64_dec(&cfg->l2_workers[owner].assigned_flows);
            kfree(candidate);
            return flow;
        }
    }
    hlist_add_head(&candidate->node, &bucket->head);
    atomic_inc(&cfg->flows.rx_count);
    atomic64_inc(&cfg->flows.rx_created);
    refcount_inc(&candidate->refs);
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

    if (!cfg || !flow_token || owner_worker < 0 ||
        owner_worker >= cfg->num_workers)
        return false;
    index = mwan_l2_rx_bucket(flow_token);
    bucket = &cfg->flows.rx[index];

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, node) {
        if (flow->flow_token != flow_token ||
            flow->owner_worker != owner_worker)
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

void mwan_l2_rx_flow_deliver(struct mwan_l2_rx_flow *flow,
                             struct sk_buff *skb, u32 flow_seq)
{
    u32 slot;

    if (!flow || !skb) {
        kfree_skb(skb);
        return;
    }

    spin_lock_bh(&flow->reorder_lock);
    if (unlikely((s32)(flow_seq - flow->expected_seq) < 0)) {
        atomic64_inc(&flow->manager->reorder_late);
        spin_unlock_bh(&flow->reorder_lock);
        kfree_skb(skb);
        return;
    }
    if (unlikely((u32)(flow_seq - flow->expected_seq) >=
                 MWAN_FLOW_RING_SIZE)) {
        atomic64_inc(&flow->manager->reorder_too_far);
        spin_unlock_bh(&flow->reorder_lock);
        kfree_skb(skb);
        return;
    }

    slot = flow_seq & MWAN_FLOW_RING_MASK;
    if (unlikely(flow->ring[slot])) {
        atomic64_inc(&flow->manager->reorder_duplicate);
        spin_unlock_bh(&flow->reorder_lock);
        kfree_skb(skb);
        return;
    }
    flow->ring[slot] = skb;
    flow->slot_time[slot] = jiffies;
    while (1) {
        u32 expected_slot = flow->expected_seq & MWAN_FLOW_RING_MASK;
        struct sk_buff *pending = flow->ring[expected_slot];

        if (!pending)
            break;
        flow->ring[expected_slot] = NULL;
        flow->slot_time[expected_slot] = 0;
        flow->expected_seq++;
        netif_rx(pending);
    }
    if (!READ_ONCE(flow->stopping))
        mod_timer(&flow->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
    spin_unlock_bh(&flow->reorder_lock);
}
