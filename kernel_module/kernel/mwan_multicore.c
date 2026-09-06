#include "mwan_multicore.h"
#include "mwan_steer.h"
#include "mwan_tunnel_balance.h"

#include <linux/cpu.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/kernel_stat.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/inet_ecn.h>
#include <net/ip.h>

#define MWAN_CPU_BP_MAX              10000U
#define MWAN_CPU_COOL_SAMPLES            3U
#define MWAN_CPU_MIN_SAMPLE_MS           10U
#define MWAN_CPU_MAX_SAMPLE_MS         1000U
#define MWAN_IDLE_TIE_BP                100U
#define MWAN_EMERGENCY_HOT_SAMPLES        3U
#define MWAN_EMERGENCY_COOL_SAMPLES       3U
#define MWAN_TX_QUEUE_HIGH_DIV             8U
#define MWAN_TX_QUEUE_LOW_DIV             32U
#define MWAN_SHED_START_BP               100U
#define MWAN_CONTROL_PQC_PORT           7090U
#define MWAN_CONTROL_BFD_PORT_1         3784U
#define MWAN_CONTROL_BFD_PORT_2         3785U
#define MWAN_CONTROL_BFD_PORT_3         4784U

static struct workqueue_struct *mwan_tx_wq;
static DEFINE_SPINLOCK(mwan_admission_lock);
static atomic64_t mwan_new_flow_admitted;
static atomic64_t mwan_no_eligible_cpu;
static void mwan_cpu_sample_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(mwan_cpu_sample_work, mwan_cpu_sample_fn);

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

static void mwan_atomic64_update_ewma(atomic64_t *ewma, u64 sample)
{
    s64 old;
    s64 next;

    do {
        old = atomic64_read(ewma);
        next = old ? old - (old >> 3) + ((s64)sample >> 3) : sample;
    } while (atomic64_cmpxchg(ewma, old, next) != old);
}

static unsigned int mwan_bp_ewma(atomic_t *value, unsigned int sample)
{
    unsigned int old = (unsigned int)atomic_read(value);
    unsigned int next = (old * 3U + sample) / 4U;

    atomic_set(value, next);
    return next;
}

static void mwan_read_cpu_accounting(int cpu, u64 *total, u64 *system,
                                     u64 *softirq, u64 *idle)
{
    struct kernel_cpustat stat;
    u64 sum = 0;
    int field;

    kcpustat_cpu_fetch(&stat, cpu);
    /* Guest is already included in user/nice.  IOWAIT remains non-idle here,
     * matching the protection goal: a CPU without executable headroom must
     * not receive another flow regardless of why it is stalled. */
    for (field = CPUTIME_USER; field < CPUTIME_GUEST; field++)
        sum += stat.cpustat[field];
    *total = sum;
    *system = stat.cpustat[CPUTIME_SYSTEM];
    *softirq = stat.cpustat[CPUTIME_SOFTIRQ];
    *idle = stat.cpustat[CPUTIME_IDLE];
}

void mwan_multicore_worker_cpu_init(struct mwan_l2_worker *worker)
{
    if (!worker)
        return;

    mwan_read_cpu_accounting(worker->cpu, &worker->cpu_prev_total,
                             &worker->cpu_prev_system,
                             &worker->cpu_prev_softirq,
                             &worker->cpu_prev_idle);
    worker->cpu_cool_samples = 0;
    worker->emergency_hot_samples = 0;
    worker->emergency_cool_samples = 0;
    worker->cpu_prev_tx_queued_packets = 0;
    worker->cpu_prev_tx_queued_bytes = 0;
    atomic_set(&worker->system_raw_bp, 0);
    atomic_set(&worker->system_ewma_bp, 0);
    atomic_set(&worker->softirq_raw_bp, 0);
    atomic_set(&worker->softirq_ewma_bp, 0);
    atomic_set(&worker->idle_raw_bp, MWAN_CPU_BP_MAX);
    atomic_set(&worker->idle_ewma_bp, MWAN_CPU_BP_MAX);
    atomic_set(&worker->busy_raw_bp, 0);
    atomic_set(&worker->busy_ewma_bp, 0);
    atomic_set(&worker->admission_blocked, 0);
    atomic_set(&worker->emergency_shed, 0);
    atomic_set(&worker->busy_peak_bp, 0);
    atomic_set(&worker->idle_min_bp, MWAN_CPU_BP_MAX);
    atomic64_set(&worker->emergency_enter_count, 0);
    atomic64_set(&worker->emergency_last_enter_ns, 0);
    atomic64_set(&worker->overload_last_drop_ns, 0);
}

static void mwan_cpu_update_worker(struct mwan_l2_worker *worker)
{
    unsigned int high_pct;
    unsigned int emergency_pct;
    unsigned int idle_unblock_pct;
    unsigned int high_bp;
    unsigned int emergency_bp;
    unsigned int idle_unblock_bp;
    unsigned int recover_load_bp;
    unsigned int raw_system;
    unsigned int raw_softirq;
    unsigned int raw_idle;
    unsigned int raw_busy;
    unsigned int ewma_system;
    unsigned int ewma_softirq;
    unsigned int ewma_idle;
    unsigned int ewma_busy;
    u64 total;
    u64 system;
    u64 softirq;
    u64 idle;
    u64 delta_total;
    u64 delta_system;
    u64 delta_softirq;
    u64 delta_idle;
    u64 tx_queued_packets;
    u64 tx_queued_bytes;
    bool emergency_load;
    bool queue_growing;
    bool queue_high;
    bool queue_low;

    if (!cpu_online(worker->cpu)) {
        atomic_set(&worker->admission_blocked, 1);
        atomic_set(&worker->emergency_shed, 1);
        worker->cpu_cool_samples = 0;
        worker->emergency_hot_samples = 0;
        worker->emergency_cool_samples = 0;
        return;
    }

    mwan_read_cpu_accounting(worker->cpu, &total, &system, &softirq, &idle);
    delta_total = total - worker->cpu_prev_total;
    delta_system = system - worker->cpu_prev_system;
    delta_softirq = softirq - worker->cpu_prev_softirq;
    delta_idle = idle - worker->cpu_prev_idle;
    worker->cpu_prev_total = total;
    worker->cpu_prev_system = system;
    worker->cpu_prev_softirq = softirq;
    worker->cpu_prev_idle = idle;
    if (unlikely(!delta_total))
        return;

    raw_system = min_t(u64, MWAN_CPU_BP_MAX,
                       div64_u64(delta_system * MWAN_CPU_BP_MAX,
                                 delta_total));
    raw_softirq = min_t(u64, MWAN_CPU_BP_MAX,
                        div64_u64(delta_softirq * MWAN_CPU_BP_MAX,
                                  delta_total));
    raw_idle = min_t(u64, MWAN_CPU_BP_MAX,
                     div64_u64(delta_idle * MWAN_CPU_BP_MAX, delta_total));
    raw_busy = MWAN_CPU_BP_MAX - raw_idle;

    atomic_set(&worker->system_raw_bp, raw_system);
    atomic_set(&worker->softirq_raw_bp, raw_softirq);
    atomic_set(&worker->idle_raw_bp, raw_idle);
    atomic_set(&worker->busy_raw_bp, raw_busy);
    if (raw_busy > (unsigned int)atomic_read(&worker->busy_peak_bp))
        atomic_set(&worker->busy_peak_bp, raw_busy);
    if (raw_idle < (unsigned int)atomic_read(&worker->idle_min_bp))
        atomic_set(&worker->idle_min_bp, raw_idle);
    ewma_system = mwan_bp_ewma(&worker->system_ewma_bp, raw_system);
    ewma_softirq = mwan_bp_ewma(&worker->softirq_ewma_bp, raw_softirq);
    ewma_idle = mwan_bp_ewma(&worker->idle_ewma_bp, raw_idle);
    ewma_busy = mwan_bp_ewma(&worker->busy_ewma_bp, raw_busy);

    high_pct = clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_high_pct), 1U, 100U);
    emergency_pct = clamp_t(unsigned int,
                            READ_ONCE(mwan_l2_emergency_pct), high_pct, 100U);
    idle_unblock_pct = clamp_t(unsigned int,
                               READ_ONCE(mwan_l2_idle_unblock_pct), 1U, 99U);
    high_bp = high_pct * 100U;
    emergency_bp = emergency_pct * 100U;
    idle_unblock_bp = idle_unblock_pct * 100U;
    recover_load_bp = min_t(unsigned int,
        READ_ONCE(mwan_l2_softirq_low_pct), high_pct - 1U) * 100U;

    emergency_load =
        max(max(raw_busy, ewma_busy),
            max(max(raw_system, ewma_system),
                max(raw_softirq, ewma_softirq))) >= emergency_bp ||
        min(raw_idle, ewma_idle) <= MWAN_CPU_BP_MAX - emergency_bp;
    tx_queued_packets = (u64)atomic64_read(&worker->tx_queued_packets);
    tx_queued_bytes = (u64)atomic64_read(&worker->tx_queued_bytes);
    queue_growing =
        tx_queued_packets > worker->cpu_prev_tx_queued_packets ||
        tx_queued_bytes > worker->cpu_prev_tx_queued_bytes;
    queue_high =
        tx_queued_packets >= MWAN_L2_QUEUE_MAX_PACKETS /
                             MWAN_TX_QUEUE_HIGH_DIV ||
        tx_queued_bytes >= MWAN_L2_QUEUE_MAX_BYTES /
                           MWAN_TX_QUEUE_HIGH_DIV;
    queue_low =
        tx_queued_packets <= MWAN_L2_QUEUE_MAX_PACKETS /
                             MWAN_TX_QUEUE_LOW_DIV &&
        tx_queued_bytes <= MWAN_L2_QUEUE_MAX_BYTES /
                           MWAN_TX_QUEUE_LOW_DIV;
    worker->cpu_prev_tx_queued_packets = tx_queued_packets;
    worker->cpu_prev_tx_queued_bytes = tx_queued_bytes;

    /* A short CPU accounting spike does not prove that TX is falling behind.
     * Require three consecutive high-load samples with a growing or already
     * material queue before shedding data. Conversely, a drained queue is
     * direct evidence of headroom and clears shedding with hysteresis. */
    if (emergency_load && (queue_growing || queue_high)) {
        if (worker->emergency_hot_samples < MWAN_EMERGENCY_HOT_SAMPLES)
            worker->emergency_hot_samples++;
        worker->emergency_cool_samples = 0;
        if (worker->emergency_hot_samples >= MWAN_EMERGENCY_HOT_SAMPLES &&
            atomic_cmpxchg(&worker->emergency_shed, 0, 1) == 0) {
            atomic64_inc(&worker->emergency_enter_count);
            atomic64_set(&worker->emergency_last_enter_ns,
                         ktime_get_ns());
        }
    } else {
        worker->emergency_hot_samples = 0;
        if (atomic_read(&worker->emergency_shed) && queue_low) {
            if (worker->emergency_cool_samples <
                MWAN_EMERGENCY_COOL_SAMPLES)
                worker->emergency_cool_samples++;
            if (worker->emergency_cool_samples >=
                MWAN_EMERGENCY_COOL_SAMPLES) {
                atomic_set(&worker->emergency_shed, 0);
                worker->emergency_cool_samples = 0;
            }
        } else {
            worker->emergency_cool_samples = 0;
        }
    }

    if (max(max(raw_busy, ewma_busy),
            max(max(raw_system, ewma_system),
                max(raw_softirq, ewma_softirq))) >= high_bp ||
        min(raw_idle, ewma_idle) <= MWAN_CPU_BP_MAX - high_bp) {
        atomic_set(&worker->admission_blocked, 1);
        worker->cpu_cool_samples = 0;
    } else if (atomic_read(&worker->admission_blocked)) {
        /* A blocked CPU is admitted again only after both the instantaneous
         * and smoothed idle signals show real headroom for three samples. */
        if (raw_idle >= idle_unblock_bp && ewma_idle >= idle_unblock_bp &&
            max(raw_system, ewma_system) <= recover_load_bp &&
            max(raw_softirq, ewma_softirq) <= recover_load_bp) {
            if (++worker->cpu_cool_samples >= MWAN_CPU_COOL_SAMPLES) {
                atomic_set(&worker->admission_blocked, 0);
                worker->cpu_cool_samples = 0;
            }
        } else {
            worker->cpu_cool_samples = 0;
        }
    }
}

static void mwan_cpu_sample_fn(struct work_struct *work)
{
    struct mwan_config *cfg;
    unsigned int sample_ms;
    int i;

    (void)work;
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && cfg->l2_workers) {
        for (i = 0; i < cfg->num_workers; i++)
            mwan_cpu_update_worker(&cfg->l2_workers[i]);
    }
    rcu_read_unlock();

    sample_ms = clamp_t(unsigned int,
                        READ_ONCE(mwan_l2_softirq_sample_ms),
                        MWAN_CPU_MIN_SAMPLE_MS, MWAN_CPU_MAX_SAMPLE_MS);
    schedule_delayed_work(&mwan_cpu_sample_work,
                          msecs_to_jiffies(sample_ms));
}

static int mwan_worker_alloc_aead(struct crypto_aead **tfm_out,
                                  struct aead_request **req_out,
                                  const u8 *key, u8 key_len,
                                  const u8 salt[MWAN_SALT_LEN])
{
    struct crypto_aead *tfm;
    struct aead_request *req;
    u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];
    int err;

    tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    if (crypto_aead_ivsize(tfm) != MWAN_RFC4106_IV_LEN) {
        err = -EINVAL;
        goto err_free_tfm;
    }
    memcpy(key_and_salt, key, key_len);
    memcpy(key_and_salt + key_len, salt, MWAN_SALT_LEN);
    err = crypto_aead_setkey(tfm, key_and_salt,
                             key_len + MWAN_SALT_LEN);
    memzero_explicit(key_and_salt, sizeof(key_and_salt));
    if (err)
        goto err_free_tfm;
    err = crypto_aead_setauthsize(tfm, MWAN_GCM_TAG_LEN);
    if (err)
        goto err_free_tfm;
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

static int mwan_worker_set_l2_keys(struct mwan_l2_worker *worker,
                                   const struct mwan_config *cfg)
{
    int err;

    err = mwan_worker_alloc_aead(&worker->tfm, &worker->req,
                                 cfg->encrypt_key, cfg->encrypt_key_len,
                                 cfg->encrypt_salt);
    if (err)
        return err;
    err = mwan_worker_alloc_aead(&worker->tx_tfm, &worker->tx_req,
                                 cfg->encrypt_key, cfg->encrypt_key_len,
                                 cfg->encrypt_salt);
    if (err)
        goto err_free_rx;
    if (cfg->prev_key_valid) {
        err = mwan_worker_alloc_aead(&worker->prev_tfm, &worker->prev_req,
                                     cfg->prev_key, cfg->prev_key_len,
                                     cfg->encrypt_salt);
        if (err)
            goto err_free_tx;
        err = mwan_worker_alloc_aead(&worker->tx_prev_tfm,
                                     &worker->tx_prev_req,
                                     cfg->prev_key, cfg->prev_key_len,
                                     cfg->encrypt_salt);
        if (err)
            goto err_free_prev_rx;
        worker->crypto_prev_id = cfg->prev_key_id;
        worker->crypto_prev_valid = true;
    }
    worker->crypto_current_id = cfg->key_id;
    return 0;

err_free_prev_rx:
    aead_request_free(worker->prev_req);
    worker->prev_req = NULL;
    crypto_free_aead(worker->prev_tfm);
    worker->prev_tfm = NULL;

err_free_tx:
    aead_request_free(worker->tx_req);
    worker->tx_req = NULL;
    crypto_free_aead(worker->tx_tfm);
    worker->tx_tfm = NULL;
err_free_rx:
    aead_request_free(worker->req);
    worker->req = NULL;
    crypto_free_aead(worker->tfm);
    worker->tfm = NULL;
    return err;
}

static void mwan_worker_free_pair(struct crypto_aead **rx_tfm,
                                  struct aead_request **rx_req,
                                  struct crypto_aead **tx_tfm,
                                  struct aead_request **tx_req)
{
    if (*rx_req)
        aead_request_free(*rx_req);
    if (*rx_tfm)
        crypto_free_aead(*rx_tfm);
    if (*tx_req)
        aead_request_free(*tx_req);
    if (*tx_tfm)
        crypto_free_aead(*tx_tfm);
    *rx_req = NULL;
    *rx_tfm = NULL;
    *tx_req = NULL;
    *tx_tfm = NULL;
}

static int mwan_worker_stage_next_key(struct mwan_l2_worker *worker,
                                      const u8 *key, u8 key_len, u8 key_id,
                                      const u8 salt[MWAN_SALT_LEN])
{
    struct crypto_aead *rx_tfm = NULL;
    struct aead_request *rx_req = NULL;
    struct crypto_aead *tx_tfm = NULL;
    struct aead_request *tx_req = NULL;
    int err;

    err = mwan_worker_alloc_aead(&rx_tfm, &rx_req, key, key_len, salt);
    if (err)
        return err;
    err = mwan_worker_alloc_aead(&tx_tfm, &tx_req, key, key_len, salt);
    if (err) {
        mwan_worker_free_pair(&rx_tfm, &rx_req, &tx_tfm, &tx_req);
        return err;
    }

    mutex_lock(&worker->crypto_lock);
    if (worker->crypto_next_valid) {
        mutex_unlock(&worker->crypto_lock);
        mwan_worker_free_pair(&rx_tfm, &rx_req, &tx_tfm, &tx_req);
        return -EEXIST;
    }
    worker->next_tfm = rx_tfm;
    worker->next_req = rx_req;
    worker->tx_next_tfm = tx_tfm;
    worker->tx_next_req = tx_req;
    worker->crypto_next_id = key_id;
    worker->crypto_next_valid = true;
    mutex_unlock(&worker->crypto_lock);
    return 0;
}

int mwan_l2_workers_stage_next_key(struct mwan_config *cfg, const u8 *key,
                                   u8 key_len, u8 key_id)
{
    int i;
    int err;

    if (!cfg || !cfg->l2_workers || !key || key_len != MWAN_MAX_KEY_LEN ||
        !key_id)
        return -EINVAL;
    for (i = 0; i < cfg->num_workers; i++) {
        err = mwan_worker_stage_next_key(&cfg->l2_workers[i], key, key_len,
                                         key_id, cfg->encrypt_salt);
        if (err)
            goto rollback;
    }
    return 0;

rollback:
    while (--i >= 0) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        mwan_worker_free_pair(&worker->next_tfm, &worker->next_req,
                              &worker->tx_next_tfm,
                              &worker->tx_next_req);
        worker->crypto_next_id = 0;
        worker->crypto_next_valid = false;
        mutex_unlock(&worker->crypto_lock);
    }
    return err;
}

int mwan_l2_workers_activate_next_key(struct mwan_config *cfg, u8 key_id)
{
    int i;

    if (!cfg || !cfg->l2_workers || !key_id)
        return -EINVAL;
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        if (!worker->crypto_next_valid ||
            worker->crypto_next_id != key_id ||
            worker->crypto_prev_valid) {
            mutex_unlock(&worker->crypto_lock);
            return -EBUSY;
        }
        mutex_unlock(&worker->crypto_lock);
    }
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        worker->prev_tfm = worker->tfm;
        worker->prev_req = worker->req;
        worker->tx_prev_tfm = worker->tx_tfm;
        worker->tx_prev_req = worker->tx_req;
        worker->crypto_prev_id = worker->crypto_current_id;
        worker->crypto_prev_valid = true;

        worker->tfm = worker->next_tfm;
        worker->req = worker->next_req;
        worker->tx_tfm = worker->tx_next_tfm;
        worker->tx_req = worker->tx_next_req;
        worker->crypto_current_id = worker->crypto_next_id;

        worker->next_tfm = NULL;
        worker->next_req = NULL;
        worker->tx_next_tfm = NULL;
        worker->tx_next_req = NULL;
        worker->crypto_next_id = 0;
        worker->crypto_next_valid = false;
        mutex_unlock(&worker->crypto_lock);
    }
    return 0;
}

int mwan_l2_workers_retire_prev_key(struct mwan_config *cfg, u8 key_id)
{
    int i;

    if (!cfg || !cfg->l2_workers || !key_id)
        return -EINVAL;
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        if (atomic_read(&worker->crypto_key_pending[key_id]) != 0)
            return -EBUSY;
        mutex_lock(&worker->crypto_lock);
        if (worker->crypto_prev_valid &&
            worker->crypto_prev_id != key_id) {
            mutex_unlock(&worker->crypto_lock);
            return -ESTALE;
        }
        mutex_unlock(&worker->crypto_lock);
    }
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        mwan_worker_free_pair(&worker->prev_tfm, &worker->prev_req,
                              &worker->tx_prev_tfm,
                              &worker->tx_prev_req);
        worker->crypto_prev_id = 0;
        worker->crypto_prev_valid = false;
        mutex_unlock(&worker->crypto_lock);
    }
    return 0;
}

int mwan_l2_workers_abort_next_key(struct mwan_config *cfg, u8 key_id)
{
    int i;

    if (!cfg || !cfg->l2_workers || !key_id)
        return -EINVAL;
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        if (worker->crypto_next_valid &&
            worker->crypto_next_id != key_id) {
            mutex_unlock(&worker->crypto_lock);
            return -ESTALE;
        }
        mutex_unlock(&worker->crypto_lock);
    }
    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *worker = &cfg->l2_workers[i];

        mutex_lock(&worker->crypto_lock);
        mwan_worker_free_pair(&worker->next_tfm, &worker->next_req,
                              &worker->tx_next_tfm,
                              &worker->tx_next_req);
        worker->crypto_next_id = 0;
        worker->crypto_next_valid = false;
        mutex_unlock(&worker->crypto_lock);
    }
    return 0;
}

static int mwan_l2_worker_crypto_lock(struct mwan_l2_worker *worker,
                                      u8 key_id, bool tx,
                                      struct crypto_aead **tfm,
                                      struct aead_request **req)
{
    if (!worker || !key_id || !tfm || !req)
        return -EINVAL;
    mutex_lock(&worker->crypto_lock);
    if (key_id == worker->crypto_current_id) {
        *tfm = tx ? worker->tx_tfm : worker->tfm;
        *req = tx ? worker->tx_req : worker->req;
    } else if (worker->crypto_prev_valid &&
               key_id == worker->crypto_prev_id) {
        *tfm = tx ? worker->tx_prev_tfm : worker->prev_tfm;
        *req = tx ? worker->tx_prev_req : worker->prev_req;
    } else if (worker->crypto_next_valid &&
               key_id == worker->crypto_next_id) {
        *tfm = tx ? worker->tx_next_tfm : worker->next_tfm;
        *req = tx ? worker->tx_next_req : worker->next_req;
    } else {
        mutex_unlock(&worker->crypto_lock);
        return -ENOKEY;
    }
    if (!*tfm || !*req) {
        mutex_unlock(&worker->crypto_lock);
        return -ENODEV;
    }
    return 0;
}

int mwan_l2_worker_tx_crypto_lock(struct mwan_l2_worker *worker, u8 key_id,
                                  struct crypto_aead **tfm,
                                  struct aead_request **req)
{
    return mwan_l2_worker_crypto_lock(worker, key_id, true, tfm, req);
}

int mwan_l2_worker_rx_crypto_lock(struct mwan_l2_worker *worker, u8 key_id,
                                  struct crypto_aead **tfm,
                                  struct aead_request **req)
{
    return mwan_l2_worker_crypto_lock(worker, key_id, false, tfm, req);
}

void mwan_l2_worker_crypto_unlock(struct mwan_l2_worker *worker)
{
    mutex_unlock(&worker->crypto_lock);
}

static u32 mwan_l2_tx_cb_checksum(const struct mwan_l2_tx_cb *cb)
{
    return lower_32_bits(cb->flow_ptr) ^ upper_32_bits(cb->flow_ptr) ^
           lower_32_bits(cb->flow_token) ^ upper_32_bits(cb->flow_token) ^
           cb->flow_seq ^ cb->accounted_bytes ^ cb->tunnel_idx ^
           cb->magic ^ ((u32)cb->encap_type << 24) ^ 0x74786362U;
}

static bool mwan_l2_tx_cb_valid(const struct mwan_config *cfg,
                                const struct sk_buff *skb,
                                const struct mwan_l2_tx_cb *cb)
{
    if (!cfg || !skb || !cb || cb->magic != MWAN_L2_TX_CB_MAGIC ||
        !cb->flow_ptr || cb->accounted_bytes != skb->truesize ||
        cb->check != mwan_l2_tx_cb_checksum(cb) ||
        cb->tunnel_idx >= cfg->num_tunnels)
        return false;
    if (cb->encap_type != MWAN_ENCAP_NONE &&
        cb->encap_type != MWAN_ENCAP_L2_PQC)
        return false;
    return cfg->tunnels[cb->tunnel_idx].encap_type == cb->encap_type;
}

static bool mwan_l2_rx_cb_valid(const struct sk_buff *skb,
                                const struct mwan_l2_rx_cb *cb)
{
    return skb && cb && cb->diag_magic == MWAN_L2_RX_CB_MAGIC &&
           cb->flow_ptr && cb->accounted_bytes == skb->truesize &&
           !(cb->dispatch_flags & ~MWAN_L2_RX_CB_NONLINEAR) &&
           cb->diag_check == mwan_l2_rx_cb_checksum(cb);
}

static bool mwan_release_rx_queue_ref(struct mwan_l2_worker *worker,
                                      const struct sk_buff *skb)
{
    struct mwan_l2_pqc_hdr l2_hdr_buf;
    const struct mwan_l2_pqc_hdr *l2_hdr;
    __be64 flow_token_be;
    u64 flow_token;
    int owner;

    if (!worker || !worker->cfg || !skb ||
        skb->len < sizeof(l2_hdr_buf))
        return false;
    l2_hdr = skb_header_pointer(skb, 0, sizeof(l2_hdr_buf), &l2_hdr_buf);
    if (!l2_hdr)
        return false;
    memcpy(&flow_token_be, &l2_hdr->flow_token, sizeof(flow_token_be));
    flow_token = be64_to_cpu(flow_token_be);
    if ((u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT))
        atomic_dec(&worker->crypto_key_pending[
            (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT)]);
    owner = (int)(worker - worker->cfg->l2_workers);
    return mwan_l2_rx_flow_release_queued(worker->cfg, flow_token, owner);
}

static bool mwan_release_tx_queue_ref(struct mwan_l2_worker *worker,
                                      struct sk_buff *skb)
{
    struct mwan_tx_flow_info info;
    int owner;

    if (!worker || !worker->cfg || !skb)
        return false;
    mwan_multicore_flow_info(skb, &info);
    owner = (int)(worker - worker->cfg->l2_workers);
    return mwan_l2_tx_flow_release_queued(worker->cfg, &info.key, owner);
}

int mwan_l2_workers_init(struct mwan_config *cfg)
{
    bool l2_pqc;
    bool bypass;
    int cpu;
    int idx = 0;
    int err;

    if (!cfg)
        return -EINVAL;
    l2_pqc = cfg->encrypt_on && cfg->encrypt_layer == 2 &&
             cfg->encrypt_type == MWAN_CRYPT_PQC_GCM;
    bypass = !cfg->encrypt_on;
    if (!l2_pqc && !bypass)
        return 0;
    if (!mwan_tx_wq)
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
        mutex_init(&worker->crypto_lock);
        skb_queue_head_init(&worker->rx_queue);
        skb_queue_head_init(&worker->tx_queue);
        INIT_WORK(&worker->work, mwan_l2_rx_worker_fn);
        INIT_WORK(&worker->tx_work, mwan_l2_tx_worker_fn);
        worker->balance_tx_bytes = kcalloc(
            cfg->num_tunnels, sizeof(*worker->balance_tx_bytes), GFP_KERNEL);
        worker->balance_last_data = kcalloc(
            cfg->num_tunnels, sizeof(*worker->balance_last_data), GFP_KERNEL);
        if (!worker->balance_tx_bytes || !worker->balance_last_data) {
            cfg->num_workers = idx + 1;
            cpus_read_unlock();
            mwan_l2_workers_cleanup(cfg);
            return -ENOMEM;
        }
        mwan_multicore_worker_cpu_init(worker);
        err = l2_pqc ? mwan_worker_set_l2_keys(worker, cfg) : 0;
        if (err) {
            pr_err("mwan_kmod: failed to initialize worker CPU %d: %d\n",
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
    if (!cfg->num_workers) {
        kfree(cfg->l2_workers);
        cfg->l2_workers = NULL;
        return -ENODEV;
    }
    cfg->worker_start_cpu = cfg->l2_workers[0].cpu;
    pr_info("mwan_kmod: initialized %d load-aware %s TX workers\n",
            cfg->num_workers, l2_pqc ? "L2-PQC" : "bypass");
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
            struct mwan_l2_rx_cb cb;
            struct mwan_l2_rx_flow *flow = NULL;
            bool cb_ok;

            memcpy(&cb, MWAN_L2_RX_CB(skb), sizeof(cb));
            cb_ok = mwan_l2_rx_cb_valid(skb, &cb);
            atomic64_dec(&worker->queued_packets);
            atomic64_sub(skb->truesize, &worker->queued_bytes);
            atomic64_inc(&worker->dropped_packets);
            if (cb_ok)
                flow = (struct mwan_l2_rx_flow *)cb.flow_ptr;
            if (cb_ok)
                atomic_dec(&worker->crypto_key_pending[
                    (u8)(cb.dispatch_flow_token >>
                         MWAN_FLOW_KEY_ID_SHIFT)]);
            if (flow) {
                atomic_dec(&flow->pending_crypto);
                mwan_l2_rx_flow_put(flow);
            } else if (!mwan_release_rx_queue_ref(worker, skb))
                pr_warn_ratelimited("mwan_kmod: unable to recover corrupt RX queue reference during cleanup on CPU %d\n",
                                    worker->cpu);
            kfree_skb(skb);
        }
        while ((skb = skb_dequeue(&worker->tx_queue)) != NULL) {
            struct mwan_l2_tx_cb cb;
            struct mwan_l2_tx_flow *flow = NULL;
            bool cb_ok;

            memcpy(&cb, MWAN_L2_TX_CB(skb), sizeof(cb));
            cb_ok = mwan_l2_tx_cb_valid(cfg, skb, &cb);
            atomic64_dec(&worker->tx_queued_packets);
            atomic64_sub(skb->truesize, &worker->tx_queued_bytes);
            atomic64_inc(&worker->tx_dropped_packets);
            if (cb_ok)
                flow = (struct mwan_l2_tx_flow *)cb.flow_ptr;
            if (cb_ok && cb.encap_type == MWAN_ENCAP_L2_PQC)
                atomic_dec(&worker->crypto_key_pending[
                    (u8)(cb.flow_token >> MWAN_FLOW_KEY_ID_SHIFT)]);
            if (flow) {
                mwan_l2_tx_flow_complete(cfg, flow);
                mwan_l2_tx_flow_put(flow);
            } else if (!mwan_release_tx_queue_ref(worker, skb))
                pr_warn_ratelimited("mwan_kmod: unable to recover corrupt TX queue reference during cleanup on CPU %d\n",
                                    worker->cpu);
            kfree_skb(skb);
        }

        if (worker->req)
            aead_request_free(worker->req);
        if (worker->tfm)
            crypto_free_aead(worker->tfm);
        if (worker->prev_req)
            aead_request_free(worker->prev_req);
        if (worker->prev_tfm)
            crypto_free_aead(worker->prev_tfm);
        if (worker->next_req)
            aead_request_free(worker->next_req);
        if (worker->next_tfm)
            crypto_free_aead(worker->next_tfm);
        if (worker->tx_prev_req)
            aead_request_free(worker->tx_prev_req);
        if (worker->tx_prev_tfm)
            crypto_free_aead(worker->tx_prev_tfm);
        if (worker->tx_next_req)
            aead_request_free(worker->tx_next_req);
        if (worker->tx_next_tfm)
            crypto_free_aead(worker->tx_next_tfm);
        if (worker->tx_req)
            aead_request_free(worker->tx_req);
        if (worker->tx_tfm)
            crypto_free_aead(worker->tx_tfm);
        kfree(worker->balance_tx_bytes);
        kfree(worker->balance_last_data);
    }
    kfree(cfg->l2_workers);
    cfg->l2_workers = NULL;
    cfg->num_workers = 0;
}

u64 mwan_multicore_worker_score(const struct mwan_l2_worker *worker)
{
    u64 queued_bytes = atomic64_read(&worker->queued_bytes) +
                       atomic64_read(&worker->tx_queued_bytes);
    u64 queued_packets = atomic64_read(&worker->queued_packets) +
                         atomic64_read(&worker->tx_queued_packets);
    u64 ewma_ns = atomic64_read(&worker->processing_ewma_ns) +
                  atomic64_read(&worker->tx_processing_ewma_ns);

    return queued_bytes + queued_packets * 2048ULL + (ewma_ns >> 3) +
           ((atomic_read(&worker->busy) || atomic_read(&worker->tx_busy)) ?
                4096ULL : 0);
}

static unsigned int mwan_worker_idle(const struct mwan_l2_worker *worker)
{
    return min((unsigned int)atomic_read(&worker->idle_raw_bp),
               (unsigned int)atomic_read(&worker->idle_ewma_bp));
}

static u64 mwan_direction_worker_score(
    const struct mwan_l2_worker *worker, bool tx)
{
    u64 queued_bytes;
    u64 queued_packets;
    u64 ewma_ns;
    bool busy;

    if (tx) {
        queued_bytes = atomic64_read(&worker->tx_queued_bytes);
        queued_packets = atomic64_read(&worker->tx_queued_packets);
        ewma_ns = atomic64_read(&worker->tx_processing_ewma_ns);
        busy = atomic_read(&worker->tx_busy) != 0;
    } else {
        queued_bytes = atomic64_read(&worker->queued_bytes);
        queued_packets = atomic64_read(&worker->queued_packets);
        ewma_ns = atomic64_read(&worker->processing_ewma_ns);
        busy = atomic_read(&worker->busy) != 0;
    }

    return queued_bytes + queued_packets * 2048ULL + (ewma_ns >> 3) +
           (busy ? 4096ULL : 0);
}

static bool mwan_tx_worker_queue_high(const struct mwan_l2_worker *worker)
{
    return atomic64_read(&worker->tx_queued_packets) >=
               MWAN_L2_QUEUE_MAX_PACKETS / MWAN_TX_QUEUE_HIGH_DIV ||
           atomic64_read(&worker->tx_queued_bytes) >=
               MWAN_L2_QUEUE_MAX_BYTES / MWAN_TX_QUEUE_HIGH_DIV;
}

static bool mwan_worker_better(const struct mwan_l2_worker *worker,
                               u64 assigned, int best,
                               const struct mwan_l2_worker *best_worker,
                               u64 best_assigned, bool tx)
{
    unsigned int idle;
    unsigned int best_idle;
    u64 score;
    u64 best_score;

    if (best < 0)
        return true;

    /* Current directional backlog is the strongest signal. A stale cached
     * flow count must never make a busy TX worker win over one that can accept
     * work immediately. */
    score = mwan_direction_worker_score(worker, tx);
    best_score = mwan_direction_worker_score(best_worker, tx);
    if (score != best_score)
        return score < best_score;

    idle = mwan_worker_idle(worker);
    best_idle = mwan_worker_idle(best_worker);
    if (idle > best_idle + MWAN_IDLE_TIE_BP)
        return true;
    if (best_idle > idle + MWAN_IDLE_TIE_BP)
        return false;
    if (assigned != best_assigned)
        return assigned < best_assigned;
    return false;
}

static int mwan_select_worker(const struct mwan_config *cfg, u32 flow_id,
                              int current_owner, bool tx,
                              bool allow_blocked_fallback)
{
    int start;
    int offset;
    int best = -1;
    u64 best_assigned = U64_MAX;

    if (!cfg || !cfg->l2_workers || cfg->num_workers <= 0)
        return -1;
    if (current_owner >= 0 && current_owner < cfg->num_workers)
        return current_owner;

    start = jhash_1word(flow_id, 0x9e3779b9U) % cfg->num_workers;
    spin_lock_bh(&mwan_admission_lock);
    for (offset = 0; offset < cfg->num_workers; offset++) {
        int idx = (start + offset) % cfg->num_workers;
        const struct mwan_l2_worker *worker = &cfg->l2_workers[idx];
        u64 assigned;

        if (!cpu_online(worker->cpu) ||
            atomic_read(&worker->admission_blocked) ||
            (tx && (atomic_read(&worker->emergency_shed) ||
                    mwan_tx_worker_queue_high(worker))))
            continue;
        /* Ownership is only a tie-breaker. In particular, cached UDP flow
         * objects from a previous traffic burst must not override live queue
         * pressure when a new burst starts. */
        assigned = tx ? atomic64_read(&worker->tx_assigned_flows) :
                        atomic64_read(&worker->assigned_flows);

        if (mwan_worker_better(worker, assigned, best,
                               best >= 0 ? &cfg->l2_workers[best] : NULL,
                               best_assigned, tx)) {
            best = idx;
            best_assigned = assigned;
        }
    }

    /* Preserve liveness when the caller explicitly identifies control
     * traffic, or when RX cannot classify the authenticated inner packet yet.
     * This fallback is used only when the normal admission pass found no CPU;
     * it chooses the online CPU with the lowest directional pressure and then
     * the highest idle headroom. */
    if (best < 0 && allow_blocked_fallback) {
        best_assigned = U64_MAX;
        for (offset = 0; offset < cfg->num_workers; offset++) {
            int idx = (start + offset) % cfg->num_workers;
            const struct mwan_l2_worker *worker = &cfg->l2_workers[idx];
            u64 assigned;

            if (!cpu_online(worker->cpu))
                continue;
            assigned = tx ? atomic64_read(&worker->tx_assigned_flows) :
                            atomic64_read(&worker->assigned_flows);
            if (mwan_worker_better(worker, assigned, best,
                                   best >= 0 ? &cfg->l2_workers[best] : NULL,
                                   best_assigned, tx)) {
                best = idx;
                best_assigned = assigned;
            }
        }
    }

    if (best >= 0) {
        if (tx)
            atomic64_inc(&cfg->l2_workers[best].tx_assigned_flows);
        else
            atomic64_inc(&cfg->l2_workers[best].assigned_flows);
        atomic64_inc(&mwan_new_flow_admitted);
    } else {
        atomic64_inc(&mwan_no_eligible_cpu);
    }
    spin_unlock_bh(&mwan_admission_lock);
    return best;
}

int mwan_l2_select_tx_worker(const struct mwan_config *cfg, u32 flow_id,
                             int current_owner,
                             bool allow_blocked_fallback)
{
    return mwan_select_worker(cfg, flow_id, current_owner, true,
                              allow_blocked_fallback);
}

int mwan_l2_select_rx_worker(const struct mwan_config *cfg, u32 flow_id,
                             int current_owner,
                             bool allow_blocked_fallback)
{
    return mwan_select_worker(cfg, flow_id, current_owner, false,
                              allow_blocked_fallback);
}

u64 mwan_multicore_admitted_get(void)
{
    return atomic64_read(&mwan_new_flow_admitted);
}

u64 mwan_multicore_no_eligible_get(void)
{
    return atomic64_read(&mwan_no_eligible_cpu);
}

void mwan_multicore_diag_reset(void)
{
    atomic64_set(&mwan_new_flow_admitted, 0);
    atomic64_set(&mwan_no_eligible_cpu, 0);
}

const char *mwan_multicore_hash_source_name(enum mwan_flow_hash_source source)
{
    switch (source) {
    case MWAN_HASH_CACHED:
        return "cached";
    case MWAN_HASH_DISSECTOR:
        return "dissector";
    case MWAN_HASH_FALLBACK:
        return "fallback";
    default:
        return "invalid";
    }
}

static bool mwan_extract_ipv4_tuple(struct sk_buff *skb,
                                    struct mwan_tx_flow_info *info,
                                    u32 *ports)
{
    struct iphdr iph_buf;
    const struct iphdr *iph;
    __be32 ports_be = 0;
    const __be32 *ports_ptr;
    int network_offset = skb_network_offset(skb);
    int ip_hlen;

    if (unlikely(network_offset < 0))
        return false;
    iph = skb_header_pointer(skb, network_offset, sizeof(iph_buf), &iph_buf);
    if (unlikely(!iph || iph->version != 4 || iph->ihl < 5))
        return false;

    info->key.saddr = iph->saddr;
    info->key.daddr = iph->daddr;
    info->key.protocol = iph->protocol;
    info->tuple_valid = true;
    ip_hlen = iph->ihl * 4;
    if (!(iph->frag_off & htons(IP_MF | IP_OFFSET)) &&
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
        ports_ptr = skb_header_pointer(skb, network_offset + ip_hlen,
                                       sizeof(ports_be), &ports_be);
        if (ports_ptr) {
            memcpy(&ports_be, ports_ptr, sizeof(ports_be));
            memcpy(&info->key.sport, ports_ptr, sizeof(info->key.sport));
            memcpy(&info->key.dport,
                   (const u8 *)ports_ptr + sizeof(info->key.sport),
                   sizeof(info->key.dport));
            *ports = (__force u32)ports_be;
        }
    }
    return true;
}

u32 mwan_multicore_flow_info(struct sk_buff *skb,
                             struct mwan_tx_flow_info *info)
{
    u32 hash;
    u32 ports = 0;

    memset(info, 0, sizeof(*info));
    info->hash_before = skb_get_hash_raw(skb);
    info->hash_was_cached = skb->l4_hash || skb->sw_hash;
    info->hash_is_l4 = skb->l4_hash;
    info->hash_is_sw = skb->sw_hash;
    hash = skb_get_hash(skb);
    if (hash) {
        info->hash_source = info->hash_was_cached ? MWAN_HASH_CACHED :
                                                   MWAN_HASH_DISSECTOR;
        mwan_extract_ipv4_tuple(skb, info, &ports);
    } else if (mwan_extract_ipv4_tuple(skb, info, &ports)) {
        ports ^= (u32)info->key.protocol << 24;
        hash = jhash_3words((__force u32)info->key.saddr,
                            (__force u32)info->key.daddr, ports,
                            0x9e3779b9U);
        info->hash_source = MWAN_HASH_FALLBACK;
    } else {
        info->hash_source = MWAN_HASH_INVALID;
    }

    info->flow_id = hash;
    /* A complete tuple is the stable identity.  Do not mix a cached skb hash
     * into it, otherwise hash provenance changes can split one connection. */
    info->key.fallback_hash = info->tuple_valid ? 0 : hash;
    return hash;
}

static bool mwan_is_control_udp_port(__be16 port)
{
    u16 host = ntohs(port);

    return host == MWAN_CONTROL_PQC_PORT ||
           host == MWAN_CONTROL_BFD_PORT_1 ||
           host == MWAN_CONTROL_BFD_PORT_2 ||
           host == MWAN_CONTROL_BFD_PORT_3;
}

enum mwan_packet_class mwan_multicore_packet_classify(struct sk_buff *skb)
{
    struct iphdr iph_buf;
    const struct iphdr *iph;
    int network_offset = skb_network_offset(skb);
    int ip_hlen;
    int ip_len;

    if (unlikely(network_offset < 0))
        return MWAN_PACKET_OTHER_DATA;
    iph = skb_header_pointer(skb, network_offset, sizeof(iph_buf), &iph_buf);
    if (!iph || iph->version != 4 || iph->ihl < 5)
        return MWAN_PACKET_OTHER_DATA;
    if (iph->frag_off & htons(IP_OFFSET))
        return MWAN_PACKET_OTHER_DATA;

    ip_hlen = iph->ihl * 4;
    ip_len = ntohs(iph->tot_len);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr tcp_buf;
        const struct tcphdr *tcp;
        int tcp_hlen;

        tcp = skb_header_pointer(skb, network_offset + ip_hlen,
                                 sizeof(tcp_buf), &tcp_buf);
        if (!tcp || tcp->doff < 5)
            return MWAN_PACKET_OTHER_DATA;
        if (tcp->syn || tcp->fin || tcp->rst)
            return MWAN_PACKET_CONTROL;
        tcp_hlen = tcp->doff * 4;
        if (ip_len < ip_hlen + tcp_hlen)
            return MWAN_PACKET_OTHER_DATA;
        if (ip_len == ip_hlen + tcp_hlen && tcp->ack)
            return MWAN_PACKET_CONTROL;
        return MWAN_PACKET_TCP_DATA;
    }
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr udp_buf;
        const struct udphdr *udp;

        udp = skb_header_pointer(skb, network_offset + ip_hlen,
                                 sizeof(udp_buf), &udp_buf);
        if (!udp || mwan_is_control_udp_port(udp->source) ||
            mwan_is_control_udp_port(udp->dest))
            return MWAN_PACKET_CONTROL;
        return MWAN_PACKET_UDP_DATA;
    }
    if (iph->protocol == IPPROTO_ICMP)
        return MWAN_PACKET_CONTROL;
    return MWAN_PACKET_OTHER_DATA;
}

static unsigned int mwan_worker_pressure(const struct mwan_l2_worker *worker)
{
    unsigned int pressure = 0;

    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->busy_raw_bp));
    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->busy_ewma_bp));
    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->system_raw_bp));
    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->system_ewma_bp));
    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->softirq_raw_bp));
    pressure = max(pressure,
                   (unsigned int)atomic_read(&worker->softirq_ewma_bp));
    return min(pressure, MWAN_CPU_BP_MAX);
}

static unsigned int mwan_drop_probability_bp(
    const struct mwan_l2_worker *worker)
{
    unsigned int emergency_pct = clamp_t(unsigned int,
        READ_ONCE(mwan_l2_emergency_pct), 1U, 100U);
    unsigned int emergency_bp = emergency_pct * 100U;
    unsigned int max_drop_bp = clamp_t(unsigned int,
        READ_ONCE(mwan_l2_max_shed_pct), 1U, 100U) * 100U;
    unsigned int pressure = mwan_worker_pressure(worker);
    u64 queued_packets = (u64)atomic64_read(&worker->tx_queued_packets);
    u64 queued_bytes = (u64)atomic64_read(&worker->tx_queued_bytes);
    unsigned int cpu_drop_bp = 0;
    unsigned int queue_pressure_bp;
    unsigned int queue_drop_bp;
    unsigned int drop_bp;

    if (pressure > emergency_bp && emergency_bp < MWAN_CPU_BP_MAX)
        cpu_drop_bp = (unsigned int)div_u64(
            (u64)(pressure - emergency_bp) * max_drop_bp,
            MWAN_CPU_BP_MAX - emergency_bp);
    queue_pressure_bp = max_t(unsigned int,
        min_t(u64, MWAN_CPU_BP_MAX,
              div64_u64(queued_packets * MWAN_CPU_BP_MAX,
                        MWAN_L2_QUEUE_MAX_PACKETS)),
        min_t(u64, MWAN_CPU_BP_MAX,
              div64_u64(queued_bytes * MWAN_CPU_BP_MAX,
                        MWAN_L2_QUEUE_MAX_BYTES)));
    queue_drop_bp = (unsigned int)div_u64(
        (u64)queue_pressure_bp * max_drop_bp, MWAN_CPU_BP_MAX);
    drop_bp = min(max(cpu_drop_bp, queue_drop_bp), max_drop_bp);

    /* Shedding is already gated by sustained CPU load plus queue pressure.
     * Start gently at 1%, rather than the previous immediate 10% step. */
    return max(min(MWAN_SHED_START_BP, max_drop_bp), drop_bp);
}

static bool mwan_tx_should_drop(struct mwan_l2_worker *worker,
                                struct sk_buff *skb,
                                enum mwan_packet_class packet_class)
{
    if (packet_class == MWAN_PACKET_CONTROL) {
        if (atomic_read(&worker->admission_blocked))
            atomic64_inc(&worker->tx_control_preserved);
        return false;
    }

    if (packet_class == MWAN_PACKET_TCP_DATA &&
        atomic_read(&worker->admission_blocked) &&
        !skb_ensure_writable(skb, skb_network_offset(skb) +
                                  sizeof(struct iphdr)) &&
        INET_ECN_set_ce(skb))
        atomic64_inc(&worker->tx_ecn_marked);

    if (!atomic_read(&worker->emergency_shed))
        return false;
    if (get_random_u32() % MWAN_CPU_BP_MAX >=
        mwan_drop_probability_bp(worker))
        return false;

    atomic64_inc(&worker->tx_overload_dropped);
    atomic64_set(&worker->overload_last_drop_ns, ktime_get_ns());
    atomic64_inc(&worker->tx_dropped_packets);
    mwan_rekey_diag_count_drop(worker->cfg, MWAN_REKEY_DROP_TX_OVERLOAD,
                               0);
    return true;
}

bool mwan_multicore_rx_congestion_feedback(struct mwan_l2_worker *worker,
                                           struct sk_buff *skb)
{
    int network_offset;

    if (!worker || !skb || !atomic_read(&worker->admission_blocked) ||
        mwan_multicore_packet_classify(skb) != MWAN_PACKET_TCP_DATA)
        return false;
    network_offset = skb_network_offset(skb);
    if (network_offset < 0 ||
        skb_ensure_writable(skb, network_offset + sizeof(struct iphdr)) ||
        !INET_ECN_set_ce(skb))
        return false;
    atomic64_inc(&worker->rx_ecn_marked);
    return true;
}

int mwan_multicore_tx_submit(struct sk_buff *skb, struct mwan_config *cfg,
                             u16 tunnel_idx,
                             const struct mwan_tx_flow_info *info,
                             struct mwan_l2_tx_flow *preselected_flow,
                             enum mwan_packet_class packet_class,
                             bool closing, u32 *flow_seq, int *owner_cpu)
{
    struct mwan_l2_tx_flow *flow;
    struct mwan_l2_worker *worker;
    struct mwan_tunnel *tun;
    unsigned int accounted_bytes;
    int owner;
    int was_scheduled;
    u32 seq = 0;

    flow = preselected_flow;
    if (!skb || !cfg || !info || tunnel_idx >= cfg->num_tunnels) {
        mwan_l2_tx_flow_put(flow);
        return -EINVAL;
    }
    if (!cfg->l2_workers || cfg->num_workers <= 0) {
        mwan_l2_tx_flow_put(flow);
        return -ENODEV;
    }
    if (!flow)
        flow = mwan_l2_tx_flow_get(cfg, &info->key, info->flow_id,
                                   packet_class == MWAN_PACKET_CONTROL,
                                   (int)tunnel_idx, false);
    if (!flow) {
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_TX_FLOW, 0);
        return -ENOSPC;
    }
    /* POST_ROUTING selected and pinned the data flow before MTU handling.
     * A mismatch here means a stale caller or a path-state transition raced
     * this packet. Drop this one packet instead of moving fragments or
     * already-normalized data onto a different-MTU tunnel. */
    if (unlikely(READ_ONCE(flow->tunnel_idx) != tunnel_idx)) {
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_TX_FLOW, 0);
        mwan_l2_tx_flow_put(flow);
        return -ESTALE;
    }
    tun = &cfg->tunnels[tunnel_idx];
    mwan_l2_tx_flow_touch(flow, closing);
    spin_lock_bh(&flow->submit_lock);
    owner = READ_ONCE(flow->owner_worker);
    if (owner < 0 || owner >= cfg->num_workers ||
        !cpu_online(cfg->l2_workers[owner].cpu)) {
        spin_unlock_bh(&flow->submit_lock);
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_TX_FLOW, 0);
        mwan_l2_tx_flow_put(flow);
        return -ENODEV;
    }
    worker = &cfg->l2_workers[owner];
    if (owner_cpu)
        *owner_cpu = worker->cpu;

    if (mwan_tx_should_drop(worker, skb, packet_class)) {
        spin_unlock_bh(&flow->submit_lock);
        mwan_l2_tx_flow_put(flow);
        return -EAGAIN;
    }

    /* ECN marking may make a cloned skb writable and change truesize. */
    accounted_bytes = skb->truesize;
    spin_lock(&worker->tx_queue.lock);
    if (worker->tx_queue.qlen >= MWAN_L2_QUEUE_MAX_PACKETS ||
        atomic64_read(&worker->tx_queued_bytes) + accounted_bytes >
            MWAN_L2_QUEUE_MAX_BYTES) {
        spin_unlock(&worker->tx_queue.lock);
        spin_unlock_bh(&flow->submit_lock);
        atomic64_inc(&worker->tx_dropped_packets);
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_TX_QUEUE, 0);
        mwan_l2_tx_flow_put(flow);
        return -ENOSPC;
    }

    if (tun->encap_type == MWAN_ENCAP_L2_PQC)
        seq = mwan_l2_tx_flow_next_seq(flow);
    BUILD_BUG_ON(sizeof(struct mwan_l2_tx_cb) > sizeof(skb->cb));
    memset(skb->cb, 0, sizeof(skb->cb));
    MWAN_L2_TX_CB(skb)->flow_ptr = (uintptr_t)flow;
    MWAN_L2_TX_CB(skb)->flow_token =
        ((u64)READ_ONCE(cfg->key_id) << MWAN_FLOW_KEY_ID_SHIFT) |
        (flow->flow_token & MWAN_FLOW_COOKIE_MASK);
    MWAN_L2_TX_CB(skb)->flow_seq = seq;
    MWAN_L2_TX_CB(skb)->accounted_bytes = accounted_bytes;
    MWAN_L2_TX_CB(skb)->tunnel_idx = (u16)tunnel_idx;
    MWAN_L2_TX_CB(skb)->magic = MWAN_L2_TX_CB_MAGIC;
    MWAN_L2_TX_CB(skb)->encap_type = (u8)tun->encap_type;
    MWAN_L2_TX_CB(skb)->check =
        mwan_l2_tx_cb_checksum(MWAN_L2_TX_CB(skb));
    if (tun->encap_type == MWAN_ENCAP_L2_PQC)
        atomic_inc(&worker->crypto_key_pending[
            (u8)(MWAN_L2_TX_CB(skb)->flow_token >>
                 MWAN_FLOW_KEY_ID_SHIFT)]);
    __skb_queue_tail(&worker->tx_queue, skb);
    atomic64_inc(&worker->tx_queued_packets);
    atomic64_add(accounted_bytes, &worker->tx_queued_bytes);
    atomic64_inc(&worker->tx_enqueued_packets);
    atomic_inc(&flow->pending_crypto);
    was_scheduled = atomic_cmpxchg(&worker->tx_scheduled, 0, 1);
    mwan_atomic64_update_max(&worker->tx_max_queued_packets,
                             worker->tx_queue.qlen);
    mwan_atomic64_update_max(&worker->tx_max_queued_bytes,
                             atomic64_read(&worker->tx_queued_bytes));
    spin_unlock(&worker->tx_queue.lock);
    spin_unlock_bh(&flow->submit_lock);

    if (flow_seq)
        *flow_seq = seq;
    if (was_scheduled == 0 && unlikely(!mwan_l2_schedule_tx_worker(worker)))
        atomic64_inc(&worker->tx_schedule_failures);
    return 0;
}

bool mwan_l2_schedule_tx_worker(struct mwan_l2_worker *worker)
{
    if (unlikely(!mwan_tx_wq))
        return false;
    if (queue_work_on(worker->cpu, mwan_tx_wq, &worker->tx_work))
        return true;
    /* False normally means the work is already pending/running.  During CPU
     * hot-unplug, retry without affinity so a sticky queue cannot strand. */
    if (work_busy(&worker->tx_work))
        return true;
    return queue_work(mwan_tx_wq, &worker->tx_work);
}

void mwan_l2_tx_worker_fn(struct work_struct *work)
{
    struct mwan_l2_worker *worker =
        container_of(work, struct mwan_l2_worker, tx_work);
    struct mwan_config *cfg = worker->cfg;
    struct sk_buff *skb;
    unsigned int batch = 0;

    atomic64_inc(&worker->tx_work_runs);
    atomic_set(&worker->tx_busy, 1);
    for (;;) {
        while ((skb = skb_dequeue(&worker->tx_queue)) != NULL) {
            struct mwan_l2_tx_cb cb;
            bool cb_ok;
            bool flow_released = false;
            u32 accounted_bytes = skb->truesize;
            u32 transmitted_bytes = skb->len;
            struct mwan_l2_tx_flow *flow;
            u64 flow_token;
            u32 flow_seq;
            u16 tunnel_idx;
            u8 encap_type;
            u64 start_ns = ktime_get_ns();
            int err;

            memcpy(&cb, MWAN_L2_TX_CB(skb), sizeof(cb));
            cb_ok = mwan_l2_tx_cb_valid(cfg, skb, &cb);
            flow = cb_ok ? (struct mwan_l2_tx_flow *)cb.flow_ptr : NULL;
            flow_token = cb_ok ? cb.flow_token : 0;
            flow_seq = cb_ok ? cb.flow_seq : 0;
            tunnel_idx = cb_ok ? cb.tunnel_idx : 0;
            encap_type = cb_ok ? cb.encap_type : 0;
            atomic64_dec(&worker->tx_queued_packets);
            atomic64_sub(accounted_bytes, &worker->tx_queued_bytes);
            if (unlikely(!cb_ok)) {
                flow_released = mwan_release_tx_queue_ref(worker, skb);
                pr_warn_ratelimited("mwan_kmod: corrupt TX worker skb metadata on CPU %d; dropping safely flow_ref_released=%u\n",
                                    worker->cpu, flow_released);
            }
            memset(skb->cb, 0, sizeof(skb->cb));

            if (!cb_ok || tunnel_idx >= cfg->num_tunnels) {
                err = -EINVAL;
            } else if (encap_type == MWAN_ENCAP_L2_PQC) {
                err = mwan_l2_pqc_encrypt_xmit(
                    skb, worker, &cfg->tunnels[tunnel_idx], flow_token,
                    flow_seq);
            } else if (encap_type == MWAN_ENCAP_NONE) {
                err = mwan_encap_none_xmit(skb, &cfg->tunnels[tunnel_idx]);
            } else {
                err = -EOPNOTSUPP;
            }

            if (cb_ok && encap_type == MWAN_ENCAP_L2_PQC)
                atomic_dec(&worker->crypto_key_pending[
                    (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT)]);

            mwan_atomic64_update_ewma(&worker->tx_processing_ewma_ns,
                                      ktime_get_ns() - start_ns);
            atomic64_inc(&worker->tx_processed_packets);
            if (unlikely(err)) {
                u8 packet_key_id =
                    (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT);

                mwan_rekey_diag_count_drop(
                    cfg, err == -ENOKEY ?
                        MWAN_REKEY_DROP_TX_CRYPTO_NO_KEY :
                        MWAN_REKEY_DROP_TX_WORKER,
                    packet_key_id);
                atomic64_inc(&worker->tx_xmit_failures);
                atomic64_inc(&worker->tx_dropped_packets);
                kfree_skb(skb);
            } else if (flow &&
                       atomic_read(&flow->balance_counted)) {
                mwan_tunnel_balance_account_bytes(
                    cfg, worker, tunnel_idx, transmitted_bytes);
            }
            if (flow) {
                mwan_l2_tx_flow_complete(cfg, flow);
                mwan_l2_tx_flow_put(flow);
            }
            if (++batch == 64) {
                batch = 0;
                cond_resched();
            }
        }

        spin_lock_bh(&worker->tx_queue.lock);
        if (!skb_queue_empty(&worker->tx_queue)) {
            spin_unlock_bh(&worker->tx_queue.lock);
            continue;
        }
        atomic_set(&worker->tx_scheduled, 0);
        spin_unlock_bh(&worker->tx_queue.lock);
        break;
    }
    atomic_set(&worker->tx_busy, 0);
}

int mwan_multicore_init(void)
{
    unsigned int sample_ms;

    mwan_multicore_diag_reset();
    mwan_tx_wq = alloc_workqueue("mwan_tx",
                                 WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!mwan_tx_wq)
        return -ENOMEM;
    sample_ms = clamp_t(unsigned int,
                        READ_ONCE(mwan_l2_softirq_sample_ms),
                        MWAN_CPU_MIN_SAMPLE_MS, MWAN_CPU_MAX_SAMPLE_MS);
    schedule_delayed_work(&mwan_cpu_sample_work,
                          msecs_to_jiffies(sample_ms));
    return 0;
}

void mwan_multicore_cleanup(void)
{
    cancel_delayed_work_sync(&mwan_cpu_sample_work);
    if (mwan_tx_wq) {
        destroy_workqueue(mwan_tx_wq);
        mwan_tx_wq = NULL;
    }
}
