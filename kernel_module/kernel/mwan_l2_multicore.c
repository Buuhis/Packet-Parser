#include "mwan_l2_multicore.h"
#include "mwan_state.h"
#include "mwan_proto.h"

#include <crypto/aead.h>
#include <linux/cpu.h>
#include <linux/jhash.h>
#include <linux/kernel_stat.h>
#include <linux/math64.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define MWAN_L2_CPU_BP_MAX              10000U
#define MWAN_L2_CPU_COOL_SAMPLES            3U
#define MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS       10U
#define MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS     1000U

static struct workqueue_struct *mwan_l2_rx_wq;
static struct workqueue_struct *mwan_l2_tx_wq;
static DEFINE_SPINLOCK(mwan_l2_admission_lock);
static unsigned long mwan_l2_next_owner_gc;
static atomic64_t mwan_l2_new_flow_admitted;
static atomic64_t mwan_l2_spread_first_admitted;
static atomic64_t mwan_l2_shared_core_admitted;
static atomic64_t mwan_l2_rejected_no_headroom;
static atomic64_t mwan_l2_owner_reclaimed;

static void mwan_l2_owner_gc(struct mwan_config *cfg);
static void mwan_l2_cpu_sample_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(mwan_l2_cpu_sample_work, mwan_l2_cpu_sample_fn);

static void mwan_l2_read_cpu_accounting(int cpu, u64 *total, u64 *system,
                                        u64 *softirq, u64 *irq, u64 *idle)
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
    *system = stat.cpustat[CPUTIME_SYSTEM];
    *softirq = stat.cpustat[CPUTIME_SOFTIRQ];
    *irq = stat.cpustat[CPUTIME_IRQ];
    *idle = stat.cpustat[CPUTIME_IDLE];
}

static unsigned int mwan_l2_cpu_ratio_bp(u64 delta, u64 delta_total)
{
    return min_t(u64, MWAN_L2_CPU_BP_MAX,
                 div64_u64(delta * MWAN_L2_CPU_BP_MAX, delta_total));
}

static unsigned int mwan_l2_cpu_ewma(unsigned int old,
                                     unsigned int sample)
{
    return old ? (old * 3U + sample) / 4U : sample;
}

static void mwan_l2_cpu_update_worker(struct mwan_l2_worker *worker)
{
    unsigned int min_idle_pct;
    unsigned int recover_idle_pct;
    unsigned int min_idle_bp;
    unsigned int recover_idle_bp;
    unsigned int system_raw;
    unsigned int softirq_raw;
    unsigned int irq_raw;
    unsigned int idle_raw;
    unsigned int system_ewma;
    unsigned int softirq_ewma;
    unsigned int irq_ewma;
    unsigned int idle_ewma;
    u64 total;
    u64 system;
    u64 softirq;
    u64 irq;
    u64 idle;
    u64 delta_total;
    u64 delta_system;
    u64 delta_softirq;
    u64 delta_irq;
    u64 delta_idle;

    if (!cpu_online(worker->cpu)) {
        atomic_set(&worker->cpu_blocked, 1);
        worker->cpu_cool_samples = 0;
        return;
    }

    mwan_l2_read_cpu_accounting(worker->cpu, &total, &system, &softirq,
                                &irq, &idle);
    delta_total = total - worker->cpu_prev_total;
    delta_system = system - worker->cpu_prev_system;
    delta_softirq = softirq - worker->cpu_prev_softirq;
    delta_irq = irq - worker->cpu_prev_irq;
    delta_idle = idle - worker->cpu_prev_idle;
    worker->cpu_prev_total = total;
    worker->cpu_prev_system = system;
    worker->cpu_prev_softirq = softirq;
    worker->cpu_prev_irq = irq;
    worker->cpu_prev_idle = idle;
    if (unlikely(delta_total == 0))
        return;

    system_raw = mwan_l2_cpu_ratio_bp(delta_system, delta_total);
    softirq_raw = mwan_l2_cpu_ratio_bp(delta_softirq, delta_total);
    irq_raw = mwan_l2_cpu_ratio_bp(delta_irq, delta_total);
    idle_raw = mwan_l2_cpu_ratio_bp(delta_idle, delta_total);
    system_ewma = mwan_l2_cpu_ewma(
        (unsigned int)atomic_read(&worker->system_ewma_bp), system_raw);
    softirq_ewma = mwan_l2_cpu_ewma(
        (unsigned int)atomic_read(&worker->softirq_ewma_bp), softirq_raw);
    irq_ewma = mwan_l2_cpu_ewma(
        (unsigned int)atomic_read(&worker->irq_ewma_bp), irq_raw);
    idle_ewma = mwan_l2_cpu_ewma(
        (unsigned int)atomic_read(&worker->idle_ewma_bp), idle_raw);

    atomic_set(&worker->system_raw_bp, system_raw);
    atomic_set(&worker->system_ewma_bp, system_ewma);
    atomic_set(&worker->softirq_raw_bp, softirq_raw);
    atomic_set(&worker->softirq_ewma_bp, softirq_ewma);
    atomic_set(&worker->irq_raw_bp, irq_raw);
    atomic_set(&worker->irq_ewma_bp, irq_ewma);
    atomic_set(&worker->idle_raw_bp, idle_raw);
    atomic_set(&worker->idle_ewma_bp, idle_ewma);

    min_idle_pct = clamp_t(unsigned int,
                           READ_ONCE(mwan_l2_idle_min_pct), 1U, 99U);
    recover_idle_pct = clamp_t(unsigned int,
                               READ_ONCE(mwan_l2_idle_recover_pct),
                               min_idle_pct + 1U, 100U);
    min_idle_bp = min_idle_pct * 100U;
    recover_idle_bp = recover_idle_pct * 100U;

    if (idle_raw < min_idle_bp || idle_ewma < min_idle_bp) {
        atomic_set(&worker->cpu_blocked, 1);
        worker->cpu_cool_samples = 0;
    } else if (atomic_read(&worker->cpu_blocked)) {
        if (idle_raw >= recover_idle_bp && idle_ewma >= recover_idle_bp) {
            if (++worker->cpu_cool_samples >= MWAN_L2_CPU_COOL_SAMPLES) {
                atomic_set(&worker->cpu_blocked, 0);
                worker->cpu_cool_samples = 0;
            }
        } else {
            worker->cpu_cool_samples = 0;
        }
    }
}

static void mwan_l2_cpu_sample_fn(struct work_struct *work)
{
    struct mwan_config *cfg;
    unsigned int sample_ms;
    int i;

    (void)work;
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && cfg->l2_workers) {
        for (i = 0; i < cfg->num_workers; i++)
            mwan_l2_cpu_update_worker(&cfg->l2_workers[i]);
        if (time_after_eq(jiffies, READ_ONCE(mwan_l2_next_owner_gc))) {
            WRITE_ONCE(mwan_l2_next_owner_gc, jiffies + HZ);
            mwan_l2_owner_gc(cfg);
        }
    }
    rcu_read_unlock();

    sample_ms = clamp_t(unsigned int,
                        READ_ONCE(mwan_l2_softirq_sample_ms),
                        MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                        MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS);
    schedule_delayed_work(&mwan_l2_cpu_sample_work,
                          msecs_to_jiffies(sample_ms));
}

static int mwan_l2_alloc_worker_aead(struct crypto_aead **tfm_out,
                                     struct aead_request **req_out,
                                     const struct mwan_config *cfg)
{
    struct crypto_aead *tfm;
    struct aead_request *req;
    u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];
    int err;

    tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        err = PTR_ERR(tfm);
        return err;
    }

    if (crypto_aead_ivsize(tfm) != MWAN_RFC4106_IV_LEN) {
        err = -EINVAL;
        goto err_free_tfm;
    }

    memcpy(key_and_salt, cfg->encrypt_key, cfg->encrypt_key_len);
    memcpy(key_and_salt + cfg->encrypt_key_len, cfg->encrypt_salt,
           MWAN_SALT_LEN);
    err = crypto_aead_setkey(tfm, key_and_salt,
                             cfg->encrypt_key_len + MWAN_SALT_LEN);
    memzero_explicit(key_and_salt, sizeof(key_and_salt));
    if (err)
        goto err_free_tfm;

    err = crypto_aead_setauthsize(tfm, MWAN_GCM_TAG_LEN);
    if (err)
        goto err_free_tfm;

    /* This request is private to the CPU worker and can be reused because a
     * worker processes its queue serially.  Avoiding one allocation/free per
     * packet removes allocator and page-clearing work from the hot path. */
    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto err_free_tfm;
    }

    *tfm_out = tfm;
    *req_out = req;
    return 0;

err_free_tfm:
    crypto_free_aead(tfm);
    return err;
}

static int mwan_l2_worker_set_keys(struct mwan_l2_worker *worker,
                                   const struct mwan_config *cfg)
{
    int err;

    err = mwan_l2_alloc_worker_aead(&worker->tfm, &worker->req, cfg);
    if (err)
        return err;

    err = mwan_l2_alloc_worker_aead(&worker->tx_tfm, &worker->tx_req, cfg);
    if (err) {
        aead_request_free(worker->req);
        worker->req = NULL;
        crypto_free_aead(worker->tfm);
        worker->tfm = NULL;
    }
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
    if (unlikely(!mwan_l2_rx_wq || !mwan_l2_tx_wq))
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
        skb_queue_head_init(&worker->tx_queue);
        INIT_WORK(&worker->work, mwan_l2_rx_worker_fn);
        INIT_WORK(&worker->tx_work, mwan_l2_tx_worker_fn);
        mwan_l2_read_cpu_accounting(cpu, &worker->cpu_prev_total,
                                    &worker->cpu_prev_system,
                                    &worker->cpu_prev_softirq,
                                    &worker->cpu_prev_irq,
                                    &worker->cpu_prev_idle);
        worker->cpu_cool_samples = 0;
        atomic_set(&worker->system_raw_bp, 0);
        atomic_set(&worker->system_ewma_bp, 0);
        atomic_set(&worker->softirq_raw_bp, 0);
        atomic_set(&worker->softirq_ewma_bp, 0);
        atomic_set(&worker->irq_raw_bp, 0);
        atomic_set(&worker->irq_ewma_bp, 0);
        atomic_set(&worker->idle_raw_bp, MWAN_L2_CPU_BP_MAX);
        atomic_set(&worker->idle_ewma_bp, MWAN_L2_CPU_BP_MAX);
        atomic_set(&worker->cpu_blocked, 0);

        err = mwan_l2_worker_set_keys(worker, cfg);
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

    for (i = 0; i < cfg->num_workers; i++) {
        cancel_work_sync(&cfg->l2_workers[i].work);
        cancel_work_sync(&cfg->l2_workers[i].tx_work);
    }

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
        while ((skb = skb_dequeue(&worker->tx_queue)) != NULL) {
            atomic64_dec(&worker->tx_queued_packets);
            atomic64_sub(skb->truesize, &worker->tx_queued_bytes);
            atomic64_inc(&worker->tx_dropped_packets);
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
        if (worker->tx_req) {
            aead_request_free(worker->tx_req);
            worker->tx_req = NULL;
        }
        if (worker->tx_tfm) {
            crypto_free_aead(worker->tx_tfm);
            worker->tx_tfm = NULL;
        }
    }

    kfree(cfg->l2_workers);
    cfg->l2_workers = NULL;
    cfg->num_workers = 0;
}

u64 mwan_l2_worker_score(const struct mwan_l2_worker *worker)
{
    u64 queued_bytes = atomic64_read(&worker->queued_bytes) +
                       atomic64_read(&worker->tx_queued_bytes);
    u64 queued_packets = atomic64_read(&worker->queued_packets) +
                         atomic64_read(&worker->tx_queued_packets);
    u64 assigned_flows = atomic64_read(&worker->assigned_flows) +
                         atomic64_read(&worker->tx_assigned_flows);
    u64 ewma_ns = atomic64_read(&worker->processing_ewma_ns) +
                  atomic64_read(&worker->tx_processing_ewma_ns);

    /* Queue pressure is the primary signal.  Assigned flow buckets prevent
     * an idle CPU from accumulating every new flow, while EWMA accounts for
     * CPUs on which the selected crypto implementation is slower. */
    return queued_bytes + queued_packets * 2048ULL +
           assigned_flows * 1024ULL + (ewma_ns >> 3) +
           ((atomic_read(&worker->busy) || atomic_read(&worker->tx_busy)) ?
                4096ULL : 0);
}

static unsigned int mwan_l2_worker_idle(const struct mwan_l2_worker *worker)
{
    unsigned int raw = (unsigned int)atomic_read(&worker->idle_raw_bp);
    unsigned int ewma = (unsigned int)atomic_read(&worker->idle_ewma_bp);

    return min(raw, ewma);
}

static bool mwan_l2_admission_better(unsigned int idle, u64 queue_bytes,
                                     u64 queue_packets, u64 assigned,
                                     int best, unsigned int best_idle,
                                     u64 best_queue_bytes,
                                     u64 best_queue_packets,
                                     u64 best_assigned)
{
    if (best < 0)
        return true;
    if (idle != best_idle)
        return idle > best_idle;
    if (queue_bytes != best_queue_bytes)
        return queue_bytes < best_queue_bytes;
    if (queue_packets != best_queue_packets)
        return queue_packets < best_queue_packets;
    if (assigned != best_assigned)
        return assigned < best_assigned;
    return false;
}

static struct mwan_l2_owner_bucket *
mwan_l2_owner_bucket(struct mwan_config *cfg, u32 flow_id, bool tx)
{
    u32 idx = jhash_1word(flow_id, 0x7f4a7c15) &
              (MWAN_L2_OWNER_BUCKETS - 1);

    return tx ? &cfg->tx_owners[idx] : &cfg->rx_owners[idx];
}

/* Select and reserve a CPU while holding the global admission lock. The scan
 * has two phases: an eligible CPU without an active flow always wins; only
 * after every eligible CPU is occupied may a new flow share a worker. */
static int mwan_l2_select_worker(const struct mwan_config *cfg, u32 flow_id,
                                 int current_owner, bool tx, bool new_flow,
                                 struct mwan_l2_select_diag *diag)
{
    unsigned int min_idle_pct;
    unsigned int min_idle_bp;
    unsigned int best_idle = 0;
    unsigned int shared_idle = 0;
    u64 best_queue_bytes = U64_MAX;
    u64 best_queue_packets = U64_MAX;
    u64 best_assigned = U64_MAX;
    u64 shared_queue_bytes = U64_MAX;
    u64 shared_queue_packets = U64_MAX;
    u64 shared_assigned = U64_MAX;
    int best = -1;
    int shared = -1;
    int start;
    int offset;
    int chosen;

    if (!cfg->l2_workers || cfg->num_workers <= 0)
        return -1;

    min_idle_pct = clamp_t(unsigned int,
                           READ_ONCE(mwan_l2_idle_min_pct), 1U, 99U);
    min_idle_bp = min_idle_pct * 100U;
    start = jhash_1word(flow_id, 0x9e3779b9) % cfg->num_workers;

    spin_lock(&mwan_l2_admission_lock);
    for (offset = 0; offset < cfg->num_workers; offset++) {
        int idx = (start + offset) % cfg->num_workers;
        const struct mwan_l2_worker *worker = &cfg->l2_workers[idx];
        unsigned int idle;
        u64 queue_bytes;
        u64 queue_packets;
        u64 direction_assigned;
        u64 assigned;

        if (!cpu_online(worker->cpu))
            continue;
        idle = mwan_l2_worker_idle(worker);
        if (atomic_read(&worker->cpu_blocked) || idle < min_idle_bp)
            continue;

        queue_bytes = atomic64_read(&worker->queued_bytes) +
                      atomic64_read(&worker->tx_queued_bytes);
        queue_packets = atomic64_read(&worker->queued_packets) +
                        atomic64_read(&worker->tx_queued_packets);
        direction_assigned = tx ?
            atomic64_read(&worker->tx_assigned_flows) :
            atomic64_read(&worker->assigned_flows);
        assigned = atomic64_read(&worker->assigned_flows) +
                   atomic64_read(&worker->tx_assigned_flows);
        if (diag)
            diag->eligible_cpus++;

        if (direction_assigned == 0 &&
            mwan_l2_admission_better(idle, queue_bytes, queue_packets,
                                     assigned, best, best_idle,
                                     best_queue_bytes, best_queue_packets,
                                     best_assigned)) {
            best = idx;
            best_idle = idle;
            best_queue_bytes = queue_bytes;
            best_queue_packets = queue_packets;
            best_assigned = assigned;
        }
        if (mwan_l2_admission_better(idle, queue_bytes, queue_packets,
                                     assigned, shared, shared_idle,
                                     shared_queue_bytes,
                                     shared_queue_packets,
                                     shared_assigned)) {
            shared = idx;
            shared_idle = idle;
            shared_queue_bytes = queue_bytes;
            shared_queue_packets = queue_packets;
            shared_assigned = assigned;
        }
    }

    chosen = best >= 0 ? best : shared;
    if (chosen < 0) {
        if (new_flow)
            atomic64_inc(&mwan_l2_rejected_no_headroom);
        spin_unlock(&mwan_l2_admission_lock);
        return -1;
    }

    if (chosen != current_owner) {
        if (current_owner >= 0 && current_owner < cfg->num_workers) {
            if (tx)
                atomic64_dec(&cfg->l2_workers[current_owner].tx_assigned_flows);
            else
                atomic64_dec(&cfg->l2_workers[current_owner].assigned_flows);
        }
        if (tx)
            atomic64_inc(&cfg->l2_workers[chosen].tx_assigned_flows);
        else
            atomic64_inc(&cfg->l2_workers[chosen].assigned_flows);
    }
    if (new_flow) {
        atomic64_inc(&mwan_l2_new_flow_admitted);
        if (best >= 0)
            atomic64_inc(&mwan_l2_spread_first_admitted);
        else
            atomic64_inc(&mwan_l2_shared_core_admitted);
    }

    if (diag) {
        const struct mwan_l2_worker *worker = &cfg->l2_workers[chosen];

        diag->ran = true;
        diag->spread_first = best >= 0;
        diag->chosen_idle_bp = mwan_l2_worker_idle(worker);
        diag->chosen_queue_bytes =
            atomic64_read(&worker->queued_bytes) +
            atomic64_read(&worker->tx_queued_bytes);
        diag->chosen_queue_packets =
            atomic64_read(&worker->queued_packets) +
            atomic64_read(&worker->tx_queued_packets);
        diag->chosen_assigned_flows =
            atomic64_read(&worker->assigned_flows) +
            atomic64_read(&worker->tx_assigned_flows);
    }
    spin_unlock(&mwan_l2_admission_lock);
    return chosen;
}

static int mwan_l2_owner_acquire(struct mwan_config *cfg, u32 flow_id,
                                 bool tx, int *owner_worker,
                                 struct mwan_l2_select_diag *diag)
{
    struct mwan_l2_owner_bucket *bucket =
        mwan_l2_owner_bucket(cfg, flow_id, tx);
    struct mwan_l2_flow_owner *entry = NULL;
    struct mwan_l2_flow_owner *free_entry = NULL;
    struct mwan_l2_flow_owner *expired_entry = NULL;
    int old_owner = -1;
    int owner;
    int way;

    spin_lock_bh(&bucket->lock);
    free_entry = NULL;
    expired_entry = NULL;
    for (way = 0; way < MWAN_L2_OWNER_WAYS; way++) {
        struct mwan_l2_flow_owner *candidate = &bucket->ways[way];

        if (candidate->valid && candidate->flow_id == flow_id) {
            entry = candidate;
            break;
        }
        if (!candidate->valid && !free_entry)
            free_entry = candidate;
        else if (candidate->valid &&
                 atomic_read(&candidate->pending_crypto) == 0 &&
                 time_after(jiffies, candidate->last_seen +
                                      MWAN_L2_FLOW_IDLE_TIMEOUT) &&
                 !expired_entry)
            expired_entry = candidate;
    }

    if (entry) {
        owner = entry->owner_worker;
        if (owner < 0 || owner >= cfg->num_workers ||
            !cpu_online(cfg->l2_workers[owner].cpu)) {
            if (atomic_read(&entry->pending_crypto) != 0) {
                spin_unlock_bh(&bucket->lock);
                return -EBUSY;
            }
            owner = mwan_l2_select_worker(cfg, flow_id,
                                          entry->owner_worker, tx, false,
                                          diag);
            if (owner < 0) {
                spin_unlock_bh(&bucket->lock);
                return -ENOSPC;
            }
            entry->owner_worker = owner;
        }
        entry->last_seen = jiffies;
        atomic_inc(&entry->pending_crypto);
        *owner_worker = owner;
        spin_unlock_bh(&bucket->lock);
        return 0;
    }

    entry = free_entry ? free_entry : expired_entry;
    if (!entry) {
        spin_unlock_bh(&bucket->lock);
        return -ENOSPC;
    }
    if (entry->valid)
        old_owner = entry->owner_worker;

    owner = mwan_l2_select_worker(cfg, flow_id, old_owner, tx, true, diag);
    if (owner < 0) {
        spin_unlock_bh(&bucket->lock);
        return -ENOSPC;
    }
    if (entry->valid)
        atomic64_inc(&mwan_l2_owner_reclaimed);
    entry->flow_id = flow_id;
    entry->owner_worker = owner;
    entry->last_seen = jiffies;
    atomic_set(&entry->pending_crypto, 1);
    WRITE_ONCE(entry->valid, true);
    *owner_worker = owner;
    spin_unlock_bh(&bucket->lock);
    return 0;
}

int mwan_l2_rx_owner_acquire(struct mwan_config *cfg, u32 flow_id,
                                    int *owner_worker,
                                    struct mwan_l2_select_diag *diag)
{
    return mwan_l2_owner_acquire(cfg, flow_id, false, owner_worker, diag);
}

int mwan_l2_tx_owner_acquire(struct mwan_config *cfg, u32 flow_id,
                             int *owner_worker)
{
    return mwan_l2_owner_acquire(cfg, flow_id, true, owner_worker, NULL);
}

void mwan_l2_flow_owner_complete(struct mwan_config *cfg, u32 flow_id,
                                 bool tx)
{
    struct mwan_l2_owner_bucket *bucket =
        mwan_l2_owner_bucket(cfg, flow_id, tx);
    int way;

    spin_lock_bh(&bucket->lock);
    for (way = 0; way < MWAN_L2_OWNER_WAYS; way++) {
        struct mwan_l2_flow_owner *entry = &bucket->ways[way];

        if (entry->valid && entry->flow_id == flow_id) {
            if (WARN_ON_ONCE(atomic_read(&entry->pending_crypto) <= 0))
                atomic_set(&entry->pending_crypto, 0);
            else
                atomic_dec(&entry->pending_crypto);
            break;
        }
    }
    spin_unlock_bh(&bucket->lock);
}

static void mwan_l2_owner_gc_direction(struct mwan_config *cfg, bool tx)
{
    int bucket_idx;

    for (bucket_idx = 0; bucket_idx < MWAN_L2_OWNER_BUCKETS; bucket_idx++) {
        struct mwan_l2_owner_bucket *bucket =
            tx ? &cfg->tx_owners[bucket_idx] :
                 &cfg->rx_owners[bucket_idx];
        int way;

        spin_lock_bh(&bucket->lock);
        for (way = 0; way < MWAN_L2_OWNER_WAYS; way++) {
            struct mwan_l2_flow_owner *entry = &bucket->ways[way];
            int owner;

            if (!entry->valid ||
                atomic_read(&entry->pending_crypto) != 0 ||
                !time_after(jiffies, entry->last_seen +
                                      MWAN_L2_FLOW_IDLE_TIMEOUT))
                continue;
            owner = entry->owner_worker;
            spin_lock(&mwan_l2_admission_lock);
            if (owner >= 0 && owner < cfg->num_workers) {
                if (tx)
                    atomic64_dec(&cfg->l2_workers[owner].tx_assigned_flows);
                else
                    atomic64_dec(&cfg->l2_workers[owner].assigned_flows);
            }
            spin_unlock(&mwan_l2_admission_lock);
            entry->valid = false;
            entry->owner_worker = -1;
            atomic64_inc(&mwan_l2_owner_reclaimed);
        }
        spin_unlock_bh(&bucket->lock);
    }
}

static void mwan_l2_owner_gc(struct mwan_config *cfg)
{
    mwan_l2_owner_gc_direction(cfg, false);
    mwan_l2_owner_gc_direction(cfg, true);
}

bool mwan_l2_schedule_tx_worker(struct mwan_l2_worker *worker)
{
    if (unlikely(!mwan_l2_tx_wq))
        return false;
    return queue_work_on(worker->cpu, mwan_l2_tx_wq, &worker->tx_work);
}

bool mwan_l2_schedule_rx_worker(struct mwan_l2_worker *worker)
{
    if (unlikely(!mwan_l2_rx_wq))
        return false;
    return queue_work_on(worker->cpu, mwan_l2_rx_wq, &worker->work);
}

void mwan_l2_multicore_diag_reset(void)
{
    atomic64_set(&mwan_l2_new_flow_admitted, 0);
    atomic64_set(&mwan_l2_spread_first_admitted, 0);
    atomic64_set(&mwan_l2_shared_core_admitted, 0);
    atomic64_set(&mwan_l2_rejected_no_headroom, 0);
    atomic64_set(&mwan_l2_owner_reclaimed, 0);
}

void mwan_l2_multicore_diag_show(struct seq_file *m)
{
    unsigned int idle_min;

    idle_min = clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_idle_min_pct), 1U, 99U);
    seq_printf(m, "idle_min=%u idle_recover=%u sample_ms=%u admitted=%lld spread_first=%lld shared=%lld rejected_no_headroom=%lld owner_reclaimed=%lld\n",
               idle_min,
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_idle_recover_pct),
                       idle_min + 1U, 100U),
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_sample_ms),
                       MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                       MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS),
               atomic64_read(&mwan_l2_new_flow_admitted),
               atomic64_read(&mwan_l2_spread_first_admitted),
               atomic64_read(&mwan_l2_shared_core_admitted),
               atomic64_read(&mwan_l2_rejected_no_headroom),
               atomic64_read(&mwan_l2_owner_reclaimed));
}

int mwan_l2_multicore_init(void)
{
    mwan_l2_multicore_diag_reset();
    mwan_l2_rx_wq = alloc_workqueue("mwan_l2rx",
                                    WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!mwan_l2_rx_wq)
        return -ENOMEM;

    mwan_l2_tx_wq = alloc_workqueue("mwan_l2tx",
                                    WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!mwan_l2_tx_wq) {
        destroy_workqueue(mwan_l2_rx_wq);
        mwan_l2_rx_wq = NULL;
        return -ENOMEM;
    }

    schedule_delayed_work(&mwan_l2_cpu_sample_work,
                          msecs_to_jiffies(clamp_t(
                              unsigned int,
                              READ_ONCE(mwan_l2_softirq_sample_ms),
                              MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                              MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS)));
    return 0;
}

void mwan_l2_multicore_cleanup(void)
{
    cancel_delayed_work_sync(&mwan_l2_cpu_sample_work);
    if (mwan_l2_rx_wq) {
        destroy_workqueue(mwan_l2_rx_wq);
        mwan_l2_rx_wq = NULL;
    }
    if (mwan_l2_tx_wq) {
        destroy_workqueue(mwan_l2_tx_wq);
        mwan_l2_tx_wq = NULL;
    }
}

