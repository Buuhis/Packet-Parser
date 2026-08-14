#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"

#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/kernel_stat.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <crypto/aead.h>
#include <net/ip.h>

/* skb->cb belongs to this module only while an encrypted frame is waiting in
 * a crypto worker queue.  Clear it before returning the skb to the network
 * stack. */
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

static struct workqueue_struct *mwan_l2_wq;
static struct dentry *mwan_debugfs_dir;

struct mwan_l2_select_diag {
    unsigned int eligible_cpus;
    unsigned int chosen_softirq_bp;
    u64 chosen_assigned_flows;
    bool all_hot_fallback;
    bool ran;
};

#define MWAN_L2_SOFTIRQ_BP_MAX          10000U
#define MWAN_L2_SOFTIRQ_TIE_BP            300U
#define MWAN_L2_SOFTIRQ_COOL_SAMPLES        3U
#define MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS       10U
#define MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS     1000U

static DEFINE_SPINLOCK(mwan_l2_rx_diag_lock);
static u32 mwan_l2_rx_diag_flows[MWAN_L2_DIAG_MAX_FLOWS];
static unsigned int mwan_l2_rx_diag_count;
static u32 mwan_l2_rx_diag_bucket_flow[MWAN_FLOW_TABLE_SIZE];
static bool mwan_l2_rx_diag_bucket_valid[MWAN_FLOW_TABLE_SIZE];

static DEFINE_SPINLOCK(mwan_l2_work_diag_lock);
static u32 mwan_l2_work_diag_flows[MWAN_L2_DIAG_MAX_FLOWS];
static unsigned int mwan_l2_work_diag_count;
static atomic_t mwan_l2_diag_generation = ATOMIC_INIT(0);
static atomic64_t mwan_l2_rx_diag_flows_count;
static atomic64_t mwan_l2_rx_diag_zero;
static atomic64_t mwan_l2_rx_diag_collisions;
static atomic64_t mwan_l2_rx_diag_fid_mismatch;
static atomic64_t mwan_l2_rx_diag_seq_mismatch;
static atomic64_t mwan_l2_rx_diag_nonce_mismatch;
static atomic64_t mwan_l2_rx_diag_cb_corrupt;
static atomic64_t mwan_l2_rx_diag_decrypt_fail;
static atomic64_t mwan_l2_rx_diag_auth_fail;
static atomic64_t mwan_l2_rx_diag_cpu_flows[NR_CPUS];
static atomic64_t mwan_l2_diag_cookie;
static atomic64_t mwan_l2_new_flow_admitted;
static atomic64_t mwan_l2_all_hot_fallback;
static DEFINE_SPINLOCK(mwan_l2_admission_lock);
static void mwan_l2_softirq_sample_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(mwan_l2_softirq_sample_work,
                            mwan_l2_softirq_sample_fn);

static void mwan_l2_worker_fn(struct work_struct *work);

static u32 mwan_l2_rx_cb_check(const struct mwan_l2_rx_cb *cb)
{
    return cb->flow_idx ^ cb->accounted_bytes ^ cb->dispatch_flow_id ^
           lower_32_bits(cb->dispatch_flow_seq) ^
           upper_32_bits(cb->dispatch_flow_seq) ^
           lower_32_bits(cb->dispatch_nonce) ^
           upper_32_bits(cb->dispatch_nonce) ^
           lower_32_bits(cb->diag_cookie) ^
           upper_32_bits(cb->diag_cookie) ^ cb->dispatch_headlen ^
           cb->dispatch_flags ^ 0x6d77616eU;
}

u32 mwan_l2_diag_generation_get(void)
{
    return (u32)atomic_read(&mwan_l2_diag_generation);
}

void mwan_l2_diag_reset_all(void)
{
    int cpu;
    u32 generation;

    mwan_l2_tx_diag_reset();

    spin_lock_bh(&mwan_l2_rx_diag_lock);
    memset(mwan_l2_rx_diag_flows, 0, sizeof(mwan_l2_rx_diag_flows));
    memset(mwan_l2_rx_diag_bucket_flow, 0,
           sizeof(mwan_l2_rx_diag_bucket_flow));
    memset(mwan_l2_rx_diag_bucket_valid, 0,
           sizeof(mwan_l2_rx_diag_bucket_valid));
    mwan_l2_rx_diag_count = 0;
    spin_unlock_bh(&mwan_l2_rx_diag_lock);

    spin_lock_bh(&mwan_l2_work_diag_lock);
    memset(mwan_l2_work_diag_flows, 0,
           sizeof(mwan_l2_work_diag_flows));
    mwan_l2_work_diag_count = 0;
    spin_unlock_bh(&mwan_l2_work_diag_lock);

    atomic64_set(&mwan_l2_rx_diag_flows_count, 0);
    atomic64_set(&mwan_l2_rx_diag_zero, 0);
    atomic64_set(&mwan_l2_rx_diag_collisions, 0);
    atomic64_set(&mwan_l2_rx_diag_fid_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_seq_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_nonce_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_cb_corrupt, 0);
    atomic64_set(&mwan_l2_rx_diag_decrypt_fail, 0);
    atomic64_set(&mwan_l2_rx_diag_auth_fail, 0);
    atomic64_set(&mwan_l2_diag_cookie, 0);
    atomic64_set(&mwan_l2_new_flow_admitted, 0);
    atomic64_set(&mwan_l2_all_hot_fallback, 0);
    for (cpu = 0; cpu < NR_CPUS; cpu++)
        atomic64_set(&mwan_l2_rx_diag_cpu_flows[cpu], 0);

    generation = (u32)atomic_inc_return(&mwan_l2_diag_generation);
    pr_info("mwan_kmod: L2D RESET g=%u\n", generation);
}

static bool mwan_l2_diag_first_flow(u32 flow_id, u32 *flows,
                                    unsigned int *flow_count,
                                    spinlock_t *lock)
{
    unsigned int count;
    unsigned int limit;
    unsigned int i;
    bool first = false;

    if (!READ_ONCE(mwan_l2_diag_enabled))
        return false;

    limit = min_t(unsigned int, READ_ONCE(mwan_l2_diag_limit),
                  MWAN_L2_DIAG_MAX_FLOWS);
    spin_lock_bh(lock);
    count = *flow_count;
    for (i = 0; i < count; i++) {
        if (flows[i] == flow_id)
            goto out;
    }
    if (count < limit) {
        flows[count] = flow_id;
        *flow_count = count + 1;
        first = true;
    }
out:
    spin_unlock_bh(lock);
    return first;
}

static void mwan_atomic64_update_max(atomic64_t *maximum, u64 value)
{
    s64 old = atomic64_read(maximum);

    while (value > (u64)old) {
        s64 observed = atomic64_cmpxchg(maximum, old, (s64)value);

        if (observed == old)
            break;
        old = observed;
    }
}

static void mwan_l2_update_ewma(struct mwan_l2_worker *worker, u64 sample_ns)
{
    s64 old;
    s64 next;

    do {
        old = atomic64_read(&worker->processing_ewma_ns);
        next = old ? old - (old >> 3) + ((s64)sample_ns >> 3) : sample_ns;
    } while (atomic64_cmpxchg(&worker->processing_ewma_ns, old, next) != old);
}

static void mwan_l2_read_cpu_accounting(int cpu, u64 *total,
                                        u64 *softirq)
{
    struct kernel_cpustat stat;
    u64 sum = 0;
    int field;

    kcpustat_cpu_fetch(&stat, cpu);
    /* Guest time is already included in user/nice accounting. Sum through
     * steal so the denominator matches elapsed accounted CPU capacity without
     * double-counting guest time. */
    for (field = CPUTIME_USER; field < CPUTIME_GUEST; field++)
        sum += stat.cpustat[field];
    *total = sum;
    *softirq = stat.cpustat[CPUTIME_SOFTIRQ];
}

static void mwan_l2_softirq_update_worker(struct mwan_l2_worker *worker)
{
    unsigned int high_pct;
    unsigned int low_pct;
    unsigned int high_bp;
    unsigned int low_bp;
    unsigned int raw_bp;
    unsigned int old_ewma;
    unsigned int ewma_bp;
    u64 total;
    u64 softirq;
    u64 delta_total;
    u64 delta_softirq;

    if (!cpu_online(worker->cpu)) {
        atomic_set(&worker->softirq_blocked, 1);
        worker->softirq_cool_samples = 0;
        return;
    }

    mwan_l2_read_cpu_accounting(worker->cpu, &total, &softirq);
    delta_total = total - worker->softirq_prev_total;
    delta_softirq = softirq - worker->softirq_prev_time;
    worker->softirq_prev_total = total;
    worker->softirq_prev_time = softirq;
    if (unlikely(delta_total == 0))
        return;

    raw_bp = min_t(u64, MWAN_L2_SOFTIRQ_BP_MAX,
                   div64_u64(delta_softirq * MWAN_L2_SOFTIRQ_BP_MAX,
                             delta_total));
    old_ewma = (unsigned int)atomic_read(&worker->softirq_ewma_bp);
    ewma_bp = (old_ewma * 3U + raw_bp) / 4U;
    atomic_set(&worker->softirq_raw_bp, raw_bp);
    atomic_set(&worker->softirq_ewma_bp, ewma_bp);

    high_pct = clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_high_pct), 1U, 100U);
    low_pct = min_t(unsigned int,
                    READ_ONCE(mwan_l2_softirq_low_pct), high_pct - 1U);
    high_bp = high_pct * 100U;
    low_bp = low_pct * 100U;

    if (raw_bp >= high_bp || ewma_bp >= high_bp) {
        atomic_set(&worker->softirq_blocked, 1);
        worker->softirq_cool_samples = 0;
    } else if (atomic_read(&worker->softirq_blocked)) {
        if (raw_bp <= low_bp && ewma_bp <= low_bp) {
            if (++worker->softirq_cool_samples >=
                MWAN_L2_SOFTIRQ_COOL_SAMPLES) {
                atomic_set(&worker->softirq_blocked, 0);
                worker->softirq_cool_samples = 0;
            }
        } else {
            worker->softirq_cool_samples = 0;
        }
    }
}

static void mwan_l2_softirq_sample_fn(struct work_struct *work)
{
    struct mwan_config *cfg;
    unsigned int sample_ms;
    int i;

    (void)work;
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && cfg->l2_workers) {
        for (i = 0; i < cfg->num_workers; i++)
            mwan_l2_softirq_update_worker(&cfg->l2_workers[i]);
    }
    rcu_read_unlock();

    sample_ms = clamp_t(unsigned int,
                        READ_ONCE(mwan_l2_softirq_sample_ms),
                        MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                        MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS);
    schedule_delayed_work(&mwan_l2_softirq_sample_work,
                          msecs_to_jiffies(sample_ms));
}

static int mwan_l2_worker_set_key(struct mwan_l2_worker *worker,
                                  const struct mwan_config *cfg)
{
    u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];
    int err;

    worker->tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0,
                                    CRYPTO_ALG_ASYNC);
    if (IS_ERR(worker->tfm)) {
        err = PTR_ERR(worker->tfm);
        worker->tfm = NULL;
        return err;
    }

    if (crypto_aead_ivsize(worker->tfm) != MWAN_RFC4106_IV_LEN) {
        err = -EINVAL;
        goto err_free_tfm;
    }

    memcpy(key_and_salt, cfg->encrypt_key, cfg->encrypt_key_len);
    memcpy(key_and_salt + cfg->encrypt_key_len, cfg->encrypt_salt,
           MWAN_SALT_LEN);
    err = crypto_aead_setkey(worker->tfm, key_and_salt,
                             cfg->encrypt_key_len + MWAN_SALT_LEN);
    memzero_explicit(key_and_salt, sizeof(key_and_salt));
    if (err)
        goto err_free_tfm;

    err = crypto_aead_setauthsize(worker->tfm, MWAN_GCM_TAG_LEN);
    if (err)
        goto err_free_tfm;

    /* This request is private to the CPU worker and can be reused because a
     * worker processes its queue serially.  Avoiding one allocation/free per
     * packet removes allocator and page-clearing work from the hot path. */
    worker->req = aead_request_alloc(worker->tfm, GFP_KERNEL);
    if (!worker->req) {
        err = -ENOMEM;
        goto err_free_tfm;
    }

    return 0;

err_free_tfm:
    if (worker->req) {
        aead_request_free(worker->req);
        worker->req = NULL;
    }
    crypto_free_aead(worker->tfm);
    worker->tfm = NULL;
    return err;
}

int mwan_l2_workers_init(struct mwan_config *cfg)
{
    int cpu;
    int idx = 0;
    int err;

    if (!cfg->encrypt_on || cfg->encrypt_layer != 2 ||
        cfg->encrypt_type != MWAN_CRYPT_PQC_GCM)
        return 0;
    if (unlikely(!mwan_l2_wq))
        return -ENODEV;

    cpus_read_lock();
    cfg->num_workers = num_online_cpus();
    if (cfg->num_workers <= 0)
        goto err_unlock_no_cpu;

    cfg->l2_workers = kcalloc(cfg->num_workers, sizeof(*cfg->l2_workers),
                              GFP_KERNEL);
    if (!cfg->l2_workers) {
        cpus_read_unlock();
        return -ENOMEM;
    }

    for_each_online_cpu(cpu) {
        struct mwan_l2_worker *worker;

        if (idx >= cfg->num_workers)
            break;
        worker = &cfg->l2_workers[idx];
        worker->cfg = cfg;
        worker->cpu = cpu;
        skb_queue_head_init(&worker->rx_queue);
        INIT_WORK(&worker->work, mwan_l2_worker_fn);
        mwan_l2_read_cpu_accounting(cpu, &worker->softirq_prev_total,
                                    &worker->softirq_prev_time);
        worker->softirq_cool_samples = 0;
        atomic_set(&worker->softirq_raw_bp, 0);
        atomic_set(&worker->softirq_ewma_bp, 0);
        atomic_set(&worker->softirq_blocked, 0);

        err = mwan_l2_worker_set_key(worker, cfg);
        if (err) {
            pr_err("mwan_kmod: failed to initialize L2 worker on CPU %d: %d\n",
                   cpu, err);
            cfg->num_workers = idx + 1;
            cpus_read_unlock();
            mwan_l2_workers_cleanup(cfg);
            return err;
        }
        idx++;
    }

    cfg->num_workers = idx;
    cpus_read_unlock();
    if (unlikely(cfg->num_workers == 0)) {
        kfree(cfg->l2_workers);
        cfg->l2_workers = NULL;
        return -ENODEV;
    }
    cfg->worker_start_cpu = cfg->l2_workers[0].cpu;
    pr_info("mwan_kmod: initialized %d load-aware L2 crypto workers\n",
            cfg->num_workers);
    return 0;

err_unlock_no_cpu:
    cpus_read_unlock();
    return -ENODEV;
}

void mwan_l2_workers_cleanup(struct mwan_config *cfg)
{
    int i;

    if (!cfg || !cfg->l2_workers)
        return;

    for (i = 0; i < cfg->num_workers; i++)
        cancel_work_sync(&cfg->l2_workers[i].work);

    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];
        struct sk_buff *skb;

        while ((skb = skb_dequeue(&worker->rx_queue)) != NULL) {
            u32 flow_idx = MWAN_L2_RX_CB(skb)->flow_idx;

            atomic64_dec(&worker->queued_packets);
            atomic64_sub(MWAN_L2_RX_CB(skb)->accounted_bytes,
                         &worker->queued_bytes);
            atomic64_inc(&worker->dropped_packets);
            if (flow_idx < MWAN_FLOW_TABLE_SIZE)
                atomic_dec(&cfg->flow_reorder[flow_idx].pending_crypto);
            kfree_skb(skb);
        }

        if (worker->req) {
            aead_request_free(worker->req);
            worker->req = NULL;
        }
        if (worker->tfm) {
            crypto_free_aead(worker->tfm);
            worker->tfm = NULL;
        }
    }

    kfree(cfg->l2_workers);
    cfg->l2_workers = NULL;
    cfg->num_workers = 0;
}

static u64 mwan_l2_worker_score(const struct mwan_l2_worker *worker)
{
    u64 queued_bytes = atomic64_read(&worker->queued_bytes);
    u64 queued_packets = atomic64_read(&worker->queued_packets);
    u64 assigned_flows = atomic64_read(&worker->assigned_flows);
    u64 ewma_ns = atomic64_read(&worker->processing_ewma_ns);

    /* Queue pressure is the primary signal.  Assigned flow buckets prevent
     * an idle CPU from accumulating every new flow, while EWMA accounts for
     * CPUs on which the selected crypto implementation is slower. */
    return queued_bytes + queued_packets * 2048ULL +
           assigned_flows * 1024ULL + (ewma_ns >> 3) +
           (atomic_read(&worker->busy) ? 4096ULL : 0);
}

static unsigned int
mwan_l2_worker_softirq_load(const struct mwan_l2_worker *worker)
{
    unsigned int raw = (unsigned int)atomic_read(&worker->softirq_raw_bp);
    unsigned int ewma = (unsigned int)atomic_read(&worker->softirq_ewma_bp);

    return max(raw, ewma);
}

static bool mwan_l2_admission_better(unsigned int load, u64 assigned,
                                     int best, unsigned int best_load,
                                     u64 best_assigned)
{
    if (best < 0)
        return true;
    if (load + MWAN_L2_SOFTIRQ_TIE_BP < best_load)
        return true;
    if (best_load + MWAN_L2_SOFTIRQ_TIE_BP < load)
        return false;
    return assigned < best_assigned;
}

/* Admit a flow bucket without an owner to the least-loaded eligible CPU.
 * All online workers are considered because the system has a small fixed CPU
 * set and this path runs only when assigning an owner, never for sticky packets.
 * The short global lock makes the assigned-flow reservation visible before
 * another concurrent flow scans, preventing a batch from herding onto the
 * same apparently-idle CPU. */
static int mwan_l2_select_worker(const struct mwan_config *cfg, u32 flow_id,
                                 int current_owner,
                                 struct mwan_l2_select_diag *diag)
{
    unsigned int high_pct;
    unsigned int high_bp;
    unsigned int best_load = U32_MAX;
    unsigned int fallback_load = U32_MAX;
    u64 best_assigned = U64_MAX;
    u64 fallback_assigned = U64_MAX;
    int best = -1;
    int fallback = -1;
    int start;
    int offset;
    int chosen;

    if (!cfg->l2_workers || cfg->num_workers <= 0)
        return -1;

    high_pct = clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_high_pct), 1U, 100U);
    high_bp = high_pct * 100U;
    start = jhash_1word(flow_id, 0x9e3779b9) % cfg->num_workers;

    spin_lock(&mwan_l2_admission_lock);
    for (offset = 0; offset < cfg->num_workers; offset++) {
        int idx = (start + offset) % cfg->num_workers;
        const struct mwan_l2_worker *worker = &cfg->l2_workers[idx];
        unsigned int load;
        u64 assigned;

        if (!cpu_online(worker->cpu))
            continue;
        load = mwan_l2_worker_softirq_load(worker);
        assigned = atomic64_read(&worker->assigned_flows);

        if (mwan_l2_admission_better(load, assigned, fallback,
                                     fallback_load, fallback_assigned)) {
            fallback = idx;
            fallback_load = load;
            fallback_assigned = assigned;
        }

        if (atomic_read(&worker->softirq_blocked) || load >= high_bp)
            continue;
        if (diag)
            diag->eligible_cpus++;
        if (mwan_l2_admission_better(load, assigned, best, best_load,
                                     best_assigned)) {
            best = idx;
            best_load = load;
            best_assigned = assigned;
        }
    }

    chosen = best >= 0 ? best : fallback;
    if (chosen >= 0 && chosen != current_owner) {
        if (current_owner >= 0 && current_owner < cfg->num_workers)
            atomic64_dec(&cfg->l2_workers[current_owner].assigned_flows);
        atomic64_inc(&cfg->l2_workers[chosen].assigned_flows);
    }
    if (chosen >= 0 && current_owner < 0)
        atomic64_inc(&mwan_l2_new_flow_admitted);
    if (best < 0 && fallback >= 0)
        atomic64_inc(&mwan_l2_all_hot_fallback);

    if (diag) {
        diag->ran = true;
        diag->all_hot_fallback = best < 0 && fallback >= 0;
        if (chosen >= 0) {
            diag->chosen_softirq_bp =
                mwan_l2_worker_softirq_load(&cfg->l2_workers[chosen]);
            diag->chosen_assigned_flows =
                atomic64_read(&cfg->l2_workers[chosen].assigned_flows);
        }
    }
    spin_unlock(&mwan_l2_admission_lock);
    return chosen;
}

static int mwan_l2_enqueue_skb(struct mwan_config *cfg, struct sk_buff *skb,
                               u32 flow_id, u64 flow_seq, u64 packet_nonce,
                               u32 rx_headlen, bool rx_nonlinear,
                               int ingress_cpu)
{
    struct mwan_per_flow_reorder *flow;
    struct mwan_l2_worker *worker;
    unsigned int accounted_bytes = skb->truesize;
    u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
    int owner;
    int new_owner;
    int was_scheduled;
    bool new_diag_flow;
    bool bucket_collision = false;
    u32 bucket_previous_flow = 0;
    u32 generation = mwan_l2_diag_generation_get();
    u64 diag_cookie = 0;
    unsigned int queued_after;
    const char *owner_reason = "sticky";
    struct mwan_l2_select_diag select_diag = { 0 };

    if (READ_ONCE(mwan_l2_diag_enabled))
        diag_cookie = (u64)atomic64_inc_return(&mwan_l2_diag_cookie);

    new_diag_flow = mwan_l2_diag_first_flow(flow_id, mwan_l2_rx_diag_flows,
                                            &mwan_l2_rx_diag_count,
                                            &mwan_l2_rx_diag_lock);
    if (READ_ONCE(mwan_l2_diag_enabled) && unlikely(flow_id == 0)) {
        atomic64_inc(&mwan_l2_rx_diag_zero);
        pr_info_ratelimited("mwan_kmod: L2D RX_ZERO_IN g=%u c=%llu hdr=%08x/%llu/%016llx head=%u nl=%u in=%d\n",
                            generation, diag_cookie, flow_id, flow_seq,
                            packet_nonce, rx_headlen, rx_nonlinear,
                            ingress_cpu);
    }
    if (new_diag_flow) {
        atomic64_inc(&mwan_l2_rx_diag_flows_count);
        spin_lock_bh(&mwan_l2_rx_diag_lock);
        if (mwan_l2_rx_diag_bucket_valid[flow_idx] &&
            mwan_l2_rx_diag_bucket_flow[flow_idx] != flow_id) {
            bucket_collision = true;
            bucket_previous_flow = mwan_l2_rx_diag_bucket_flow[flow_idx];
            atomic64_inc(&mwan_l2_rx_diag_collisions);
        } else if (!mwan_l2_rx_diag_bucket_valid[flow_idx]) {
            mwan_l2_rx_diag_bucket_valid[flow_idx] = true;
            mwan_l2_rx_diag_bucket_flow[flow_idx] = flow_id;
        }
        spin_unlock_bh(&mwan_l2_rx_diag_lock);
    }

    flow = &cfg->flow_reorder[flow_idx];
    spin_lock_bh(&flow->owner_lock);
    owner = atomic_read(&flow->owner_worker);

    if (owner < 0 || owner >= cfg->num_workers) {
        if (unlikely(atomic_read(&flow->pending_crypto) != 0)) {
            spin_unlock_bh(&flow->owner_lock);
            return -EBUSY;
        }
        owner_reason = "new";
        new_owner = mwan_l2_select_worker(cfg, flow_id, owner, &select_diag);
    } else if (!cpu_online(cfg->l2_workers[owner].cpu)) {
        /* Never move an active flow while packets may still be executing on
         * the old CPU.  Dropping during the rare hot-unplug transition is
         * safer than decrypting the same flow concurrently on two CPUs. */
        if (atomic_read(&flow->pending_crypto) != 0) {
            spin_unlock_bh(&flow->owner_lock);
            return -EBUSY;
        }
        owner_reason = "offline";
        new_owner = mwan_l2_select_worker(cfg, flow_id, owner, &select_diag);
    } else {
        /* Load never migrates an owned flow. A hot owner remains sticky and
         * is merely excluded from admission decisions for other new flows. */
        new_owner = owner;
    }

    if (new_owner < 0) {
        spin_unlock_bh(&flow->owner_lock);
        return -ENODEV;
    }
    if (new_owner != owner) {
        atomic_set(&flow->owner_worker, new_owner);
        owner = new_owner;
    }

    worker = &cfg->l2_workers[owner];
    spin_lock(&worker->rx_queue.lock);
    if (worker->rx_queue.qlen >= MWAN_L2_QUEUE_MAX_PACKETS ||
        atomic64_read(&worker->queued_bytes) + accounted_bytes >
            MWAN_L2_QUEUE_MAX_BYTES) {
        spin_unlock(&worker->rx_queue.lock);
        atomic64_inc(&worker->dropped_packets);
        spin_unlock_bh(&flow->owner_lock);
        return -ENOSPC;
    }

    BUILD_BUG_ON(sizeof(struct mwan_l2_rx_cb) > sizeof(skb->cb));
    MWAN_L2_RX_CB(skb)->flow_idx = flow_idx;
    MWAN_L2_RX_CB(skb)->accounted_bytes = accounted_bytes;
    MWAN_L2_RX_CB(skb)->dispatch_flow_id = flow_id;
    MWAN_L2_RX_CB(skb)->dispatch_flow_seq = flow_seq;
    MWAN_L2_RX_CB(skb)->dispatch_nonce = packet_nonce;
    MWAN_L2_RX_CB(skb)->diag_cookie = diag_cookie;
    MWAN_L2_RX_CB(skb)->dispatch_headlen =
        min_t(u32, rx_headlen, U16_MAX);
    MWAN_L2_RX_CB(skb)->dispatch_flags =
        rx_nonlinear ? MWAN_L2_RX_CB_NONLINEAR : 0;
    MWAN_L2_RX_CB(skb)->reserved = 0;
    MWAN_L2_RX_CB(skb)->diag_magic = MWAN_L2_RX_CB_MAGIC;
    MWAN_L2_RX_CB(skb)->diag_check =
        mwan_l2_rx_cb_check(MWAN_L2_RX_CB(skb));
    __skb_queue_tail(&worker->rx_queue, skb);
    queued_after = worker->rx_queue.qlen;
    atomic64_inc(&worker->queued_packets);
    atomic64_add(accounted_bytes, &worker->queued_bytes);
    atomic64_inc(&worker->enqueued_packets);
    atomic_inc(&flow->pending_crypto);
    flow->last_seen = jiffies;
    /* Change 0 -> 1 while holding the same queue lock used by the worker's
     * empty-queue handoff.  This makes queue ownership and scheduled state a
     * single transition instead of two independently visible operations. */
    was_scheduled = atomic_cmpxchg(&worker->scheduled, 0, 1);
    mwan_atomic64_update_max(&worker->max_queued_packets,
                             worker->rx_queue.qlen);
    mwan_atomic64_update_max(&worker->max_queued_bytes,
                             atomic64_read(&worker->queued_bytes));
    spin_unlock(&worker->rx_queue.lock);
    spin_unlock_bh(&flow->owner_lock);

    if (new_diag_flow) {
        if (worker->cpu >= 0 && worker->cpu < NR_CPUS)
            atomic64_inc(&mwan_l2_rx_diag_cpu_flows[worker->cpu]);

        if (bucket_collision)
            pr_info("mwan_kmod: L2D COLL g=%u b=%u new=%08x prev=%08x owner=%d/%d\n",
                    generation, flow_idx, flow_id, bucket_previous_flow,
                    owner, worker->cpu);

        if (select_diag.ran) {
            if (flow_id == 0)
                pr_info("mwan_kmod: L2D RX_ZERO g=%u c=%llu hdr=%08x/%llu/%016llx head=%u nl=%u b=%u in=%d reason=%s eligible=%u soft_bp=%u flows=%llu fallback=%u owner=%d/%d q=%u\n",
                        generation, diag_cookie, flow_id, flow_seq,
                        packet_nonce, rx_headlen, rx_nonlinear, flow_idx,
                        ingress_cpu, owner_reason,
                        select_diag.eligible_cpus,
                        select_diag.chosen_softirq_bp,
                        select_diag.chosen_assigned_flows,
                        select_diag.all_hot_fallback, owner, worker->cpu,
                        queued_after);
            else
                pr_info("mwan_kmod: L2D RX g=%u c=%llu hdr=%08x/%llu/%016llx head=%u nl=%u b=%u in=%d reason=%s eligible=%u soft_bp=%u flows=%llu fallback=%u owner=%d/%d q=%u\n",
                        generation, diag_cookie, flow_id, flow_seq,
                        packet_nonce, rx_headlen, rx_nonlinear, flow_idx,
                        ingress_cpu, owner_reason,
                        select_diag.eligible_cpus,
                        select_diag.chosen_softirq_bp,
                        select_diag.chosen_assigned_flows,
                        select_diag.all_hot_fallback, owner, worker->cpu,
                        queued_after);
        } else if (flow_id == 0) {
            pr_info("mwan_kmod: L2D RX_ZERO g=%u c=%llu hdr=%08x/%llu/%016llx head=%u nl=%u b=%u in=%d reason=%s owner=%d/%d q=%u\n",
                    generation, diag_cookie, flow_id, flow_seq, packet_nonce,
                    rx_headlen, rx_nonlinear, flow_idx, ingress_cpu,
                    owner_reason, owner, worker->cpu, queued_after);
        } else {
            pr_info("mwan_kmod: L2D RX g=%u c=%llu hdr=%08x/%llu/%016llx head=%u nl=%u b=%u in=%d reason=%s owner=%d/%d q=%u\n",
                    generation, diag_cookie, flow_id, flow_seq, packet_nonce,
                    rx_headlen, rx_nonlinear, flow_idx, ingress_cpu,
                    owner_reason, owner, worker->cpu, queued_after);
        }
    }

    if (was_scheduled == 0 &&
        unlikely(!queue_work_on(worker->cpu, mwan_l2_wq, &worker->work)))
        atomic64_inc(&worker->schedule_failures);
    return 0;
}

static int l2_pqc_decrypt_skb(struct sk_buff *skb,
                              struct mwan_l2_worker *worker,
                              u32 *out_flow_id, u64 *out_flow_seq,
                              u64 *out_packet_nonce)
{
    u8 iv_buf[MWAN_RFC4106_IV_LEN];
    u64 packet_nonce;
    u64 flow_seq;
    u32 flow_id;
    __be32 flow_id_be;
    __be64 flow_seq_be;
    __be64 nonce_be;
    struct aead_request *req = worker->req;
    struct mwan_l2_pqc_hdr *l2_hdr;
    int ciphertext_len;
    int err;

    if (skb_is_nonlinear(skb) && unlikely(skb_linearize(skb)))
        return -ENOMEM;
    if (skb_cow(skb, 0))
        return -ENOMEM;
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN)
        return -EINVAL;
    if (unlikely(!worker->tfm || !req))
        return -ENODEV;

    l2_hdr = (struct mwan_l2_pqc_hdr *)skb->data;
    memcpy(&flow_id_be, &l2_hdr->flow_id, sizeof(flow_id_be));
    memcpy(&flow_seq_be, &l2_hdr->flow_seq, sizeof(flow_seq_be));
    memcpy(&nonce_be, &l2_hdr->packet_nonce, sizeof(nonce_be));
    flow_id = be32_to_cpu(flow_id_be);
    flow_seq = be64_to_cpu(flow_seq_be);
    packet_nonce = be64_to_cpu(nonce_be);
    if (unlikely(packet_nonce == 0))
        return -EINVAL;

    if (out_flow_id)
        *out_flow_id = flow_id;
    if (out_flow_seq)
        *out_flow_seq = flow_seq;
    if (out_packet_nonce)
        *out_packet_nonce = packet_nonce;
    memcpy(iv_buf, &nonce_be, sizeof(nonce_be));

    ciphertext_len = skb->len - MWAN_L2_HDR_LEN;
    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], skb->data, MWAN_L2_HDR_LEN);
        nents = skb_to_sgvec(skb, &sg[1], MWAN_L2_HDR_LEN,
                             ciphertext_len);
        if (unlikely(nents < 0))
            return -EINVAL;

        aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
        aead_request_set_ad(req, MWAN_L2_HDR_LEN);
        err = crypto_aead_decrypt(req);
    }

    if (err) {
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d)\n",
                            err);
        return err;
    }

    if (unlikely(skb_cow(skb, ETH_HLEN)))
        return -ENOMEM;

    memmove(skb->data + MWAN_L2_HDR_LEN - ETH_HLEN,
            skb->data - ETH_HLEN, ETH_HLEN);
    skb_pull(skb, MWAN_L2_HDR_LEN);
    skb_trim(skb, skb->len - MWAN_GCM_TAG_LEN);

    skb_set_mac_header(skb, -ETH_HLEN);
    eth_hdr(skb)->h_proto = htons(ETH_P_IP);
    skb->protocol = htons(ETH_P_IP);
    skb_reset_network_header(skb);
    skb->ip_summed = CHECKSUM_NONE;
    skb->encapsulation = 0;

    /* The old hash describes the encrypted/outer frame.  Recompute it from
     * the restored inner tuple before reinjection. */
    skb_clear_hash(skb);
    skb_get_hash(skb);
    return 0;
}

void mwan_reorder_timeout(struct timer_list *t)
{
    struct mwan_config *cfg = container_of(t, struct mwan_config,
                                           reorder_timer);
    bool restart = false;
    int f;

    for (f = 0; f < MWAN_FLOW_TABLE_SIZE; f++) {
        struct mwan_per_flow_reorder *flow = &cfg->flow_reorder[f];
        int i;

        spin_lock_bh(&flow->drain_lock);
        while (1) {
            u32 slot = (u32)(atomic64_read(&flow->expected_seq) &
                             MWAN_FLOW_RING_MASK);
            struct sk_buff *skb = flow->ring[slot];

            if (skb) {
                flow->ring[slot] = NULL;
                flow->slot_time[slot] = 0;
                atomic64_inc(&flow->expected_seq);
                netif_rx(skb);
            } else {
                bool timed_out = false;

                for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
                    if (flow->ring[i] && flow->slot_time[i] &&
                        time_after_eq(jiffies, flow->slot_time[i] +
                                      MWAN_REORDER_TIMEOUT)) {
                        timed_out = true;
                        break;
                    }
                }
                if (!timed_out)
                    break;
                atomic64_inc(&flow->expected_seq);
            }
        }

        for (i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
            if (flow->ring[i]) {
                restart = true;
                break;
            }
        }
        spin_unlock_bh(&flow->drain_lock);
    }

    if (restart)
        mod_timer(&cfg->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
}

static void mwan_l2_deliver_decrypted(struct mwan_config *cfg,
                                      struct sk_buff *skb, u32 flow_id,
                                      u64 flow_seq)
{
    u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
    struct mwan_per_flow_reorder *flow = &cfg->flow_reorder[flow_idx];
    u32 slot;

    spin_lock_bh(&flow->drain_lock);
    {
        u64 expected = atomic64_read(&flow->expected_seq);

        if (unlikely(expected == 1 || flow_seq > expected + 128)) {
            atomic64_set(&flow->expected_seq, flow_seq);
            expected = flow_seq;
        }
        if (unlikely(flow_seq < expected)) {
            spin_unlock_bh(&flow->drain_lock);
            kfree_skb(skb);
            return;
        }
    }

    slot = flow_seq & MWAN_FLOW_RING_MASK;
    if (unlikely(flow->ring[slot] != NULL)) {
        kfree_skb(flow->ring[slot]);
        flow->ring[slot] = NULL;
        flow->slot_time[slot] = 0;
    }
    flow->ring[slot] = skb;
    flow->slot_time[slot] = jiffies;

    while (1) {
        u64 expected = atomic64_read(&flow->expected_seq);
        u32 expected_slot = expected & MWAN_FLOW_RING_MASK;
        struct sk_buff *pending = flow->ring[expected_slot];

        if (!pending)
            break;
        flow->ring[expected_slot] = NULL;
        flow->slot_time[expected_slot] = 0;
        atomic64_inc(&flow->expected_seq);
        netif_rx(pending);
    }
    spin_unlock_bh(&flow->drain_lock);
    timer_reduce(&cfg->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
}

static void mwan_l2_worker_fn(struct work_struct *work)
{
    struct mwan_l2_worker *worker = container_of(work, struct mwan_l2_worker,
                                                 work);
    struct mwan_config *cfg = worker->cfg;
    struct sk_buff *skb;
    unsigned int batch = 0;

    atomic64_inc(&worker->work_runs);
    atomic_set(&worker->busy, 1);
    for (;;) {
        while ((skb = skb_dequeue(&worker->rx_queue)) != NULL) {
            u32 flow_idx = MWAN_L2_RX_CB(skb)->flow_idx;
            u32 accounted_bytes = MWAN_L2_RX_CB(skb)->accounted_bytes;
            u32 dispatch_flow_id = MWAN_L2_RX_CB(skb)->dispatch_flow_id;
            u64 dispatch_flow_seq = MWAN_L2_RX_CB(skb)->dispatch_flow_seq;
            u64 dispatch_nonce = MWAN_L2_RX_CB(skb)->dispatch_nonce;
            u64 diag_cookie = MWAN_L2_RX_CB(skb)->diag_cookie;
            u32 dispatch_headlen = MWAN_L2_RX_CB(skb)->dispatch_headlen;
            bool dispatch_nonlinear =
                MWAN_L2_RX_CB(skb)->dispatch_flags &
                MWAN_L2_RX_CB_NONLINEAR;
            bool cb_ok = MWAN_L2_RX_CB(skb)->diag_magic ==
                         MWAN_L2_RX_CB_MAGIC &&
                         MWAN_L2_RX_CB(skb)->diag_check ==
                         mwan_l2_rx_cb_check(MWAN_L2_RX_CB(skb));
            u32 flow_id = 0;
            u64 flow_seq = 0;
            u64 packet_nonce = 0;
            u64 start_ns = ktime_get_ns();
            int ret;

            atomic64_dec(&worker->queued_packets);
            atomic64_sub(accounted_bytes, &worker->queued_bytes);
            ret = l2_pqc_decrypt_skb(skb, worker, &flow_id, &flow_seq,
                                     &packet_nonce);
            mwan_l2_update_ewma(worker, ktime_get_ns() - start_ns);
            atomic64_inc(&worker->processed_packets);

            if (READ_ONCE(mwan_l2_diag_enabled)) {
                bool fid_ok = dispatch_flow_id == flow_id;
                bool seq_ok = dispatch_flow_seq == flow_seq;
                bool nonce_ok = dispatch_nonce == packet_nonce;
                bool first_work;
                u32 generation = mwan_l2_diag_generation_get();

                if (!fid_ok)
                    atomic64_inc(&mwan_l2_rx_diag_fid_mismatch);
                if (!seq_ok)
                    atomic64_inc(&mwan_l2_rx_diag_seq_mismatch);
                if (!nonce_ok)
                    atomic64_inc(&mwan_l2_rx_diag_nonce_mismatch);
                if (!cb_ok)
                    atomic64_inc(&mwan_l2_rx_diag_cb_corrupt);
                if (ret) {
                    atomic64_inc(&mwan_l2_rx_diag_decrypt_fail);
                    if (ret == -EBADMSG)
                        atomic64_inc(&mwan_l2_rx_diag_auth_fail);
                }

                first_work = mwan_l2_diag_first_flow(
                    dispatch_flow_id, mwan_l2_work_diag_flows,
                    &mwan_l2_work_diag_count, &mwan_l2_work_diag_lock);
                if (unlikely(ret || !cb_ok || !fid_ok || !seq_ok ||
                             !nonce_ok))
                    pr_info_ratelimited("mwan_kmod: L2D WORK_BAD g=%u c=%llu cb_ok=%u cb=%08x/%llu/%016llx hdr=%08x/%llu/%016llx rx_head=%u rx_nl=%u cpu=%d/%u fid_ok=%u seq_ok=%u nonce_ok=%u decrypt_status=%s auth=%s err=%d\n",
                                        generation, diag_cookie,
                                        cb_ok,
                                        dispatch_flow_id, dispatch_flow_seq,
                                        dispatch_nonce, flow_id, flow_seq,
                                        packet_nonce, dispatch_headlen,
                                        dispatch_nonlinear,
                                        worker->cpu, raw_smp_processor_id(),
                                        fid_ok, seq_ok, nonce_ok,
                                        ret ? "fail" : "ok",
                                        ret == -EBADMSG ? "fail" :
                                        (ret ? "na" : "ok"), ret);
                else if (first_work)
                    pr_info("mwan_kmod: L2D WORK g=%u c=%llu hdr=%08x/%llu/%016llx cpu=%d/%u fid_ok=1 seq_ok=1 auth=ok\n",
                            generation, diag_cookie, flow_id, flow_seq,
                            packet_nonce, worker->cpu,
                            raw_smp_processor_id());
            }

            memset(skb->cb, 0, sizeof(skb->cb));
            if (unlikely(ret < 0)) {
                atomic64_inc(&worker->decrypt_failures);
                kfree_skb(skb);
            } else {
                mwan_l2_deliver_decrypted(cfg, skb, flow_id, flow_seq);
            }

            if (flow_idx < MWAN_FLOW_TABLE_SIZE)
                atomic_dec(&cfg->flow_reorder[flow_idx].pending_crypto);
            if (++batch == 64) {
                batch = 0;
                cond_resched();
            }
        }

        spin_lock_bh(&worker->rx_queue.lock);
        if (!skb_queue_empty(&worker->rx_queue)) {
            spin_unlock_bh(&worker->rx_queue.lock);
            continue;
        }
        atomic_set(&worker->scheduled, 0);
        spin_unlock_bh(&worker->rx_queue.lock);
        break;
    }
    atomic_set(&worker->busy, 0);
}

static int mwan_l2_stats_show(struct seq_file *m, void *unused)
{
    struct mwan_config *cfg;
    int i;

    (void)unused;
    seq_puts(m, "cpu queued_pkts queued_bytes max_pkts max_bytes enqueued processed drops decrypt_fail owned_flows ewma_ns work_runs schedule_fail busy score soft_raw_bp soft_ewma_bp blocked\n");
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->l2_workers) {
        seq_puts(m, "L2-PQC workers are not active\n");
        rcu_read_unlock();
        return 0;
    }

    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *w = &cfg->l2_workers[i];

        seq_printf(m, "%d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %d %llu %d %d %d\n",
                   w->cpu,
                   atomic64_read(&w->queued_packets),
                   atomic64_read(&w->queued_bytes),
                   atomic64_read(&w->max_queued_packets),
                   atomic64_read(&w->max_queued_bytes),
                   atomic64_read(&w->enqueued_packets),
                   atomic64_read(&w->processed_packets),
                   atomic64_read(&w->dropped_packets),
                   atomic64_read(&w->decrypt_failures),
                   atomic64_read(&w->assigned_flows),
                   atomic64_read(&w->processing_ewma_ns),
                   atomic64_read(&w->work_runs),
                   atomic64_read(&w->schedule_failures),
                   atomic_read(&w->busy),
                   mwan_l2_worker_score(w),
                   atomic_read(&w->softirq_raw_bp),
                   atomic_read(&w->softirq_ewma_bp),
                   atomic_read(&w->softirq_blocked));
    }
    rcu_read_unlock();
    return 0;
}

static int mwan_l2_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_l2_stats_show, inode->i_private);
}

static const struct file_operations mwan_l2_stats_fops = {
    .owner = THIS_MODULE,
    .open = mwan_l2_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int mwan_l2_diag_show(struct seq_file *m, void *unused)
{
    int cpu;

    (void)unused;
    seq_printf(m, "generation=%u enabled=%u limit=%u\n",
               mwan_l2_diag_generation_get(),
               READ_ONCE(mwan_l2_diag_enabled),
               min_t(unsigned int, READ_ONCE(mwan_l2_diag_limit),
                     MWAN_L2_DIAG_MAX_FLOWS));
    seq_printf(m, "tx_flows=%llu tx_zero_packets=%llu\n",
               mwan_l2_tx_diag_flows_get(), mwan_l2_tx_diag_zero_get());
    seq_printf(m, "rx_flows=%lld rx_zero_packets=%lld collisions=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_flows_count),
               atomic64_read(&mwan_l2_rx_diag_zero),
               atomic64_read(&mwan_l2_rx_diag_collisions));
    seq_printf(m, "fid_mismatch=%lld seq_mismatch=%lld nonce_mismatch=%lld cb_corrupt=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_fid_mismatch),
               atomic64_read(&mwan_l2_rx_diag_seq_mismatch),
               atomic64_read(&mwan_l2_rx_diag_nonce_mismatch),
               atomic64_read(&mwan_l2_rx_diag_cb_corrupt));
    seq_printf(m, "decrypt_fail=%lld auth_fail=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_decrypt_fail),
               atomic64_read(&mwan_l2_rx_diag_auth_fail));
    seq_printf(m, "softirq_high=%u softirq_low=%u sample_ms=%u admitted=%lld all_hot_fallback=%lld\n",
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_high_pct), 1U, 100U),
               min_t(unsigned int, READ_ONCE(mwan_l2_softirq_low_pct),
                     clamp_t(unsigned int,
                             READ_ONCE(mwan_l2_softirq_high_pct),
                             1U, 100U) - 1U),
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_sample_ms),
                       MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                       MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS),
               atomic64_read(&mwan_l2_new_flow_admitted),
               atomic64_read(&mwan_l2_all_hot_fallback));
    seq_puts(m, "cpu_flows:");
    cpus_read_lock();
    for_each_online_cpu(cpu)
        seq_printf(m, " %d=%lld", cpu,
                   atomic64_read(&mwan_l2_rx_diag_cpu_flows[cpu]));
    cpus_read_unlock();
    seq_putc(m, '\n');
    return 0;
}

static int mwan_l2_diag_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_l2_diag_show, inode->i_private);
}

static const struct file_operations mwan_l2_diag_fops = {
    .owner = THIS_MODULE,
    .open = mwan_l2_diag_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt,
                             struct net_device *orig_dev)
{
    struct mwan_l2_pqc_hdr l2_hdr_buf;
    const struct mwan_l2_pqc_hdr *l2_hdr;
    struct mwan_config *cfg;
    __be32 flow_id_be;
    __be64 flow_seq_be;
    __be64 nonce_be;
    u32 flow_id;
    u64 flow_seq;
    u64 packet_nonce;
    u32 rx_headlen;
    bool rx_nonlinear;
    int ingress_cpu;
    int ret;

    (void)dev;
    (void)pt;
    (void)orig_dev;
    if (!skb)
        return NET_RX_DROP;
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    /* A packet_type handler may receive a fully non-linear skb with
     * skb_headlen(skb) == 0. Read only the authenticated 20-byte prefix here;
     * skb_header_pointer() returns skb->data on the linear fast path and
     * copies just the prefix into l2_hdr_buf otherwise. The selected worker
     * remains responsible for linearizing the encrypted payload. */
    l2_hdr = skb_header_pointer(skb, 0, sizeof(l2_hdr_buf), &l2_hdr_buf);
    if (unlikely(!l2_hdr)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    memcpy(&flow_id_be, &l2_hdr->flow_id, sizeof(flow_id_be));
    memcpy(&flow_seq_be, &l2_hdr->flow_seq, sizeof(flow_seq_be));
    memcpy(&nonce_be, &l2_hdr->packet_nonce, sizeof(nonce_be));
    flow_id = be32_to_cpu(flow_id_be);
    flow_seq = be64_to_cpu(flow_seq_be);
    packet_nonce = be64_to_cpu(nonce_be);
    rx_headlen = skb_headlen(skb);
    rx_nonlinear = skb_is_nonlinear(skb);
    ingress_cpu = raw_smp_processor_id();

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->encrypt_on || !cfg->l2_workers) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    ret = mwan_l2_enqueue_skb(cfg, skb, flow_id, flow_seq, packet_nonce,
                              rx_headlen, rx_nonlinear, ingress_cpu);
    rcu_read_unlock();
    if (unlikely(ret < 0)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    return NET_RX_SUCCESS;
}

static struct packet_type l2_pqc_packet_type __read_mostly = {
    .type = cpu_to_be16(MWAN_L2_PQC_ETHERTYPE),
    .func = l2_pqc_rx_handler,
};

int mwan_decap_l2_pqc_init(void)
{
    mwan_l2_diag_reset_all();
    mwan_l2_wq = alloc_workqueue("mwan_l2rx",
                                 WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!mwan_l2_wq)
        return -ENOMEM;

    mwan_debugfs_dir = debugfs_create_dir("mwan_kmod", NULL);
    if (IS_ERR_OR_NULL(mwan_debugfs_dir)) {
        pr_warn("mwan_kmod: debugfs is unavailable; L2 stats disabled\n");
        mwan_debugfs_dir = NULL;
    } else {
        debugfs_create_file("l2_workers", 0444, mwan_debugfs_dir, NULL,
                            &mwan_l2_stats_fops);
        debugfs_create_file("l2_diag", 0444, mwan_debugfs_dir, NULL,
                            &mwan_l2_diag_fops);
    }
    dev_add_pack(&l2_pqc_packet_type);
    schedule_delayed_work(&mwan_l2_softirq_sample_work,
                          msecs_to_jiffies(clamp_t(
                              unsigned int,
                              READ_ONCE(mwan_l2_softirq_sample_ms),
                              MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                              MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS)));
    pr_info("mwan_kmod: registered load-aware L2-PQC handler (0x%04x)\n",
            MWAN_L2_PQC_ETHERTYPE);
    return 0;
}

void mwan_decap_l2_pqc_cleanup(void)
{
    dev_remove_pack(&l2_pqc_packet_type);
    cancel_delayed_work_sync(&mwan_l2_softirq_sample_work);
    debugfs_remove_recursive(mwan_debugfs_dir);
    mwan_debugfs_dir = NULL;
    if (mwan_l2_wq) {
        destroy_workqueue(mwan_l2_wq);
        mwan_l2_wq = NULL;
    }
    pr_info("mwan_kmod: unregistered L2-PQC packet handler\n");
}
