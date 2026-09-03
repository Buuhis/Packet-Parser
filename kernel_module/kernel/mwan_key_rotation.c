#include "mwan_key_rotation.h"

#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/string.h>

const char *mwan_rekey_diag_phase_name(int phase)
{
    switch (phase) {
    case MWAN_REKEY_DIAG_STABLE:
        return "STABLE";
    case MWAN_REKEY_DIAG_STAGING:
        return "STAGING";
    case MWAN_REKEY_DIAG_STAGED:
        return "STAGED";
    case MWAN_REKEY_DIAG_ACTIVATING:
        return "ACTIVATING";
    case MWAN_REKEY_DIAG_DRAINING:
        return "DRAINING";
    case MWAN_REKEY_DIAG_RETIRING:
        return "RETIRING";
    case MWAN_REKEY_DIAG_ABORTING:
        return "ABORTING";
    default:
        return "INVALID";
    }
}

const char *mwan_rekey_drop_reason_name(int reason)
{
    switch (reason) {
    case MWAN_REKEY_DROP_RX_KEY_REJECT:
        return "rx_key_reject";
    case MWAN_REKEY_DROP_RX_CRYPTO_NO_KEY:
        return "rx_crypto_no_key";
    case MWAN_REKEY_DROP_RX_AUTH:
        return "rx_auth";
    case MWAN_REKEY_DROP_RX_CRYPTO_OTHER:
        return "rx_crypto_other";
    case MWAN_REKEY_DROP_RX_QUEUE:
        return "rx_queue";
    case MWAN_REKEY_DROP_RX_FLOW:
        return "rx_flow";
    case MWAN_REKEY_DROP_TX_CRYPTO_NO_KEY:
        return "tx_crypto_no_key";
    case MWAN_REKEY_DROP_TX_WORKER:
        return "tx_worker";
    case MWAN_REKEY_DROP_TX_QUEUE:
        return "tx_queue";
    case MWAN_REKEY_DROP_TX_OVERLOAD:
        return "tx_overload";
    case MWAN_REKEY_DROP_TX_FLOW:
        return "tx_flow";
    case MWAN_REKEY_DROP_REORDER_LATE:
        return "reorder_late";
    case MWAN_REKEY_DROP_REORDER_TOO_FAR:
        return "reorder_too_far";
    default:
        return "invalid";
    }
}

void mwan_rekey_diag_init(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return;
    atomic_set(&cfg->rekey_diag.phase,
               cfg->prev_key_valid ? MWAN_REKEY_DIAG_DRAINING :
                                     MWAN_REKEY_DIAG_STABLE);
    atomic64_set(&cfg->rekey_diag.event_seq, 0);
    for (i = 0; i < MWAN_REKEY_DIAG_PHASE_MAX; i++)
        atomic64_set(&cfg->rekey_diag.drop_by_phase[i], 0);
    for (i = 0; i < MWAN_REKEY_DROP_REASON_MAX; i++)
        atomic64_set(&cfg->rekey_diag.drop_by_reason[i], 0);
    atomic64_set(&cfg->rekey_diag.prev_rejected_while_retiring, 0);
}

void mwan_rekey_diag_reset(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return;
    atomic64_set(&cfg->rekey_diag.event_seq, 0);
    for (i = 0; i < MWAN_REKEY_DIAG_PHASE_MAX; i++)
        atomic64_set(&cfg->rekey_diag.drop_by_phase[i], 0);
    for (i = 0; i < MWAN_REKEY_DROP_REASON_MAX; i++)
        atomic64_set(&cfg->rekey_diag.drop_by_reason[i], 0);
    atomic64_set(&cfg->rekey_diag.prev_rejected_while_retiring, 0);
}

void mwan_rekey_diag_count_drop(struct mwan_config *cfg,
                                enum mwan_rekey_drop_reason reason,
                                u8 packet_key_id)
{
    int phase;

    if (!cfg || reason < 0 || reason >= MWAN_REKEY_DROP_REASON_MAX)
        return;
    phase = atomic_read(&cfg->rekey_diag.phase);
    if (phase < 0 || phase >= MWAN_REKEY_DIAG_PHASE_MAX)
        phase = MWAN_REKEY_DIAG_STABLE;
    atomic64_inc(&cfg->rekey_diag.drop_by_phase[phase]);
    atomic64_inc(&cfg->rekey_diag.drop_by_reason[reason]);
    if (reason == MWAN_REKEY_DROP_RX_KEY_REJECT &&
        phase == MWAN_REKEY_DIAG_RETIRING && packet_key_id != 0 &&
        packet_key_id == READ_ONCE(cfg->prev_key_id))
        atomic64_inc(&cfg->rekey_diag.prev_rejected_while_retiring);
}

static void mwan_rekey_diag_event(struct mwan_config *cfg, int phase,
                                  const char *event, u64 epoch,
                                  u8 target_key_id, int ret,
                                  u64 started_ns)
{
    u64 rx_q = 0, tx_q = 0, rx_drop = 0, tx_drop = 0;
    u64 decrypt_fail = 0, tx_fail = 0, overload_drop = 0;
    u64 pending_current = 0, pending_prev = 0, pending_next = 0;
    u64 now_ns = ktime_get_ns();
    u64 seq;
    int i;

    if (!cfg || phase < 0 || phase >= MWAN_REKEY_DIAG_PHASE_MAX)
        return;
    atomic_set(&cfg->rekey_diag.phase, phase);
    seq = (u64)atomic64_inc_return(&cfg->rekey_diag.event_seq);
    if (cfg->l2_workers) {
        for (i = 0; i < cfg->num_workers; i++) {
            struct mwan_l2_worker *worker = &cfg->l2_workers[i];

            rx_q += (u64)atomic64_read(&worker->queued_packets);
            tx_q += (u64)atomic64_read(&worker->tx_queued_packets);
            rx_drop += (u64)atomic64_read(&worker->dropped_packets);
            tx_drop += (u64)atomic64_read(&worker->tx_dropped_packets);
            decrypt_fail +=
                (u64)atomic64_read(&worker->decrypt_failures);
            tx_fail += (u64)atomic64_read(&worker->tx_xmit_failures);
            overload_drop +=
                (u64)atomic64_read(&worker->tx_overload_dropped);
            if (cfg->key_id)
                pending_current += (u64)max_t(
                    int, atomic_read(&worker->crypto_key_pending[
                        cfg->key_id]), 0);
            if (cfg->prev_key_id)
                pending_prev += (u64)max_t(
                    int, atomic_read(&worker->crypto_key_pending[
                        cfg->prev_key_id]), 0);
            if (cfg->next_key_id)
                pending_next += (u64)max_t(
                    int, atomic_read(&worker->crypto_key_pending[
                        cfg->next_key_id]), 0);
        }
    }

    pr_info("mwan_kmod: RKD seq=%llu mono_ns=%llu event=%s phase=%s node=%u cfg_gen=%u epoch=%llu target=%u ret=%d duration_us=%llu keys=%u/%u/%u valid=%u/%u q=%llu/%llu drops=%llu/%llu decrypt=%llu tx_fail=%llu overload=%llu pending=%llu/%llu/%llu reorder=%lld/%lld prev_reject_retire=%lld\n",
            seq, now_ns, event, mwan_rekey_diag_phase_name(phase),
            cfg->node_id, cfg->generation, epoch, target_key_id, ret,
            started_ns && now_ns >= started_ns ?
                (now_ns - started_ns) / 1000 : 0,
            cfg->key_id, cfg->prev_key_id, cfg->next_key_id,
            cfg->prev_key_valid, cfg->next_key_valid,
            rx_q, tx_q, rx_drop, tx_drop, decrypt_fail, tx_fail,
            overload_drop, pending_current, pending_prev, pending_next,
            atomic64_read(&cfg->flows.reorder_too_far),
            atomic64_read(&cfg->flows.reorder_late),
            atomic64_read(
                &cfg->rekey_diag.prev_rejected_while_retiring));
}

static int mwan_key_cfg_validate(const struct mwan_config *cfg, u32 node_id,
                                 u32 generation)
{
    if (!cfg)
        return -ENOENT;
    if (cfg->node_id != node_id || cfg->generation != generation)
        return -ESTALE;
    if (!cfg->encrypt_on || cfg->encrypt_layer != 2 ||
        cfg->encrypt_type != MWAN_CRYPT_PQC_GCM || !cfg->l2_workers)
        return -EOPNOTSUPP;
    return 0;
}

int mwan_state_stage_pqc_key(u32 node_id, u32 generation, u64 epoch,
                             u8 key_id, const u8 *key, u8 key_len)
{
    struct mwan_config *cfg;
    u64 started_ns = 0;
    int old_phase = MWAN_REKEY_DIAG_STABLE;
    int ret;

    if (!epoch || !key_id || !key || key_len != MWAN_MAX_KEY_LEN)
        return -EINVAL;

    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    ret = mwan_key_cfg_validate(cfg, node_id, generation);
    if (ret)
        goto out;

    if (cfg->rekey_epoch == epoch && cfg->next_key_valid &&
        cfg->next_key_id == key_id &&
        memcmp(cfg->next_key, key, key_len) == 0) {
        ret = 0;
        goto out;
    }
    if (cfg->next_key_valid || key_id == cfg->key_id ||
        (cfg->prev_key_valid && key_id == cfg->prev_key_id)) {
        ret = -EEXIST;
        goto out;
    }

    old_phase = atomic_read(&cfg->rekey_diag.phase);
    started_ns = ktime_get_ns();
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_STAGING,
                          "STAGE_BEGIN", epoch, key_id, 0, started_ns);
    ret = mwan_l2_workers_stage_next_key(cfg, key, key_len, key_id);
    if (ret) {
        mwan_rekey_diag_event(cfg, old_phase, "STAGE_FAIL", epoch,
                              key_id, ret, started_ns);
        goto out;
    }
    memcpy(cfg->next_key, key, key_len);
    cfg->next_key_len = key_len;
    cfg->next_key_id = key_id;
    cfg->next_key_valid = true;
    cfg->rekey_epoch = epoch;
    cfg->key_state = MWAN_PQC_KEY_STAGED;
    pr_info("mwan_kmod: PQC-REKEY STAGED node=%u epoch=%llu current=%u next=%u\n",
            node_id, epoch, cfg->key_id, key_id);
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_STAGED,
                          "STAGE_DONE", epoch, key_id, 0, started_ns);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_activate_pqc_key(u32 node_id, u32 generation, u64 epoch,
                                u8 key_id)
{
    struct mwan_config *cfg;
    u64 started_ns = 0;
    int ret;

    if (!epoch || !key_id)
        return -EINVAL;
    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    ret = mwan_key_cfg_validate(cfg, node_id, generation);
    if (ret)
        goto out;
    if (cfg->rekey_epoch == epoch && cfg->key_id == key_id &&
        cfg->key_state == MWAN_PQC_KEY_ACTIVE_WITH_PREV) {
        ret = 0;
        goto out;
    }
    if (cfg->rekey_epoch != epoch || !cfg->next_key_valid ||
        cfg->next_key_id != key_id) {
        ret = -ESTALE;
        goto out;
    }
    if (cfg->prev_key_valid) {
        ret = -EBUSY;
        goto out;
    }

    started_ns = ktime_get_ns();
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_ACTIVATING,
                          "ACTIVATE_BEGIN", epoch, key_id, 0,
                          started_ns);
    ret = mwan_l2_workers_activate_next_key(cfg, key_id);
    if (ret) {
        mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_STAGED,
                              "ACTIVATE_FAIL", epoch, key_id, ret,
                              started_ns);
        goto out;
    }
    memcpy(cfg->prev_key, cfg->encrypt_key, cfg->encrypt_key_len);
    cfg->prev_key_len = cfg->encrypt_key_len;
    cfg->prev_key_id = cfg->key_id;
    cfg->prev_key_valid = true;
    memcpy(cfg->encrypt_key, cfg->next_key, cfg->next_key_len);
    cfg->encrypt_key_len = cfg->next_key_len;
    cfg->key_id = cfg->next_key_id;
    memzero_explicit(cfg->next_key, sizeof(cfg->next_key));
    cfg->next_key_len = 0;
    cfg->next_key_id = 0;
    cfg->next_key_valid = false;
    cfg->key_state = MWAN_PQC_KEY_ACTIVE_WITH_PREV;
    pr_info("mwan_kmod: PQC-REKEY ACTIVATED node=%u epoch=%llu current=%u prev=%u\n",
            node_id, epoch, cfg->key_id, cfg->prev_key_id);
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_DRAINING,
                          "ACTIVATE_DONE", epoch, key_id, 0,
                          started_ns);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_retire_pqc_key(u32 node_id, u32 generation, u64 epoch,
                              u8 key_id)
{
    struct mwan_config *cfg;
    u64 started_ns = 0;
    int ret;

    if (!key_id)
        return -EINVAL;
    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    ret = mwan_key_cfg_validate(cfg, node_id, generation);
    if (ret)
        goto out;
    if (cfg->rekey_epoch != epoch) {
        ret = -ESTALE;
        goto out;
    }
    if (!cfg->prev_key_valid) {
        ret = 0;
        goto out;
    }
    if (cfg->prev_key_id != key_id) {
        ret = -ESTALE;
        goto out;
    }

    started_ns = ktime_get_ns();
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_RETIRING,
                          "RETIRE_BEGIN", epoch, key_id, 0,
                          started_ns);
    /* Stop admitting new frames carrying PREV before inspecting the
     * per-worker pending counters.  synchronize_rcu() closes the window for
     * RX handlers that observed prev_key_valid before it was cleared. */
    WRITE_ONCE(cfg->prev_key_valid, false);
    synchronize_rcu();
    ret = mwan_l2_workers_retire_prev_key(cfg, key_id);
    if (ret) {
        WRITE_ONCE(cfg->prev_key_valid, true);
        mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_DRAINING,
                              ret == -EBUSY ? "RETIRE_BUSY" :
                                              "RETIRE_FAIL",
                              epoch, key_id, ret, started_ns);
        goto out;
    }
    memzero_explicit(cfg->prev_key, sizeof(cfg->prev_key));
    cfg->prev_key_len = 0;
    cfg->prev_key_id = 0;
    cfg->key_state = MWAN_PQC_KEY_STABLE;
    pr_info("mwan_kmod: PQC-REKEY RETIRED node=%u epoch=%llu current=%u\n",
            node_id, epoch, cfg->key_id);
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_STABLE,
                          "RETIRE_DONE", epoch, key_id, 0,
                          started_ns);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_abort_pqc_key(u32 node_id, u32 generation, u64 epoch,
                             u8 key_id)
{
    struct mwan_config *cfg;
    u64 started_ns = 0;
    int old_phase = MWAN_REKEY_DIAG_STABLE;
    int ret;

    if (!epoch || !key_id)
        return -EINVAL;
    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    ret = mwan_key_cfg_validate(cfg, node_id, generation);
    if (ret)
        goto out;
    if (cfg->rekey_epoch != epoch) {
        ret = -ESTALE;
        goto out;
    }
    if (!cfg->next_key_valid) {
        ret = 0;
        goto out;
    }
    if (cfg->next_key_id != key_id) {
        ret = -ESTALE;
        goto out;
    }
    old_phase = atomic_read(&cfg->rekey_diag.phase);
    started_ns = ktime_get_ns();
    mwan_rekey_diag_event(cfg, MWAN_REKEY_DIAG_ABORTING,
                          "ABORT_BEGIN", epoch, key_id, 0,
                          started_ns);
    ret = mwan_l2_workers_abort_next_key(cfg, key_id);
    if (ret) {
        mwan_rekey_diag_event(cfg, old_phase, "ABORT_FAIL", epoch,
                              key_id, ret, started_ns);
        goto out;
    }
    memzero_explicit(cfg->next_key, sizeof(cfg->next_key));
    cfg->next_key_len = 0;
    cfg->next_key_id = 0;
    cfg->next_key_valid = false;
    cfg->rekey_epoch = 0;
    cfg->key_state = cfg->prev_key_valid ?
        MWAN_PQC_KEY_ACTIVE_WITH_PREV : MWAN_PQC_KEY_STABLE;
    pr_info("mwan_kmod: PQC-REKEY ABORTED node=%u epoch=%llu current=%u\n",
            node_id, epoch, cfg->key_id);
    mwan_rekey_diag_event(
        cfg, cfg->prev_key_valid ? MWAN_REKEY_DIAG_DRAINING :
                                  MWAN_REKEY_DIAG_STABLE,
        "ABORT_DONE", epoch, key_id, 0, started_ns);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_get_pqc_key_state(u32 node_id, u32 *generation, u64 *epoch,
                                 u8 *state, u8 *current_id, u8 *prev_id,
                                 u8 *next_id)
{
    struct mwan_config *cfg;
    int ret = 0;

    if (!generation || !epoch || !state || !current_id || !prev_id ||
        !next_id)
        return -EINVAL;
    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    if (!cfg || cfg->node_id != node_id) {
        ret = -ENOENT;
        goto out;
    }
    *generation = cfg->generation;
    *epoch = cfg->rekey_epoch;
    *state = cfg->key_state;
    *current_id = cfg->key_id;
    *prev_id = cfg->prev_key_valid ? cfg->prev_key_id : 0;
    *next_id = cfg->next_key_valid ? cfg->next_key_id : 0;
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}
