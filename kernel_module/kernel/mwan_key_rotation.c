#include "mwan_key_rotation.h"

#include <linux/errno.h>
#include <linux/string.h>

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

    ret = mwan_l2_workers_stage_next_key(cfg, key, key_len, key_id);
    if (ret)
        goto out;
    memcpy(cfg->next_key, key, key_len);
    cfg->next_key_len = key_len;
    cfg->next_key_id = key_id;
    cfg->next_key_valid = true;
    cfg->rekey_epoch = epoch;
    cfg->key_state = MWAN_PQC_KEY_STAGED;
    pr_info("mwan_kmod: PQC-REKEY STAGED node=%u epoch=%llu current=%u next=%u\n",
            node_id, epoch, cfg->key_id, key_id);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_activate_pqc_key(u32 node_id, u32 generation, u64 epoch,
                                u8 key_id)
{
    struct mwan_config *cfg;
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

    ret = mwan_l2_workers_activate_next_key(cfg, key_id);
    if (ret)
        goto out;
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
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_retire_pqc_key(u32 node_id, u32 generation, u64 epoch,
                              u8 key_id)
{
    struct mwan_config *cfg;
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

    /* Stop admitting new frames carrying PREV before inspecting the
     * per-worker pending counters.  synchronize_rcu() closes the window for
     * RX handlers that observed prev_key_valid before it was cleared. */
    WRITE_ONCE(cfg->prev_key_valid, false);
    synchronize_rcu();
    ret = mwan_l2_workers_retire_prev_key(cfg, key_id);
    if (ret) {
        WRITE_ONCE(cfg->prev_key_valid, true);
        goto out;
    }
    memzero_explicit(cfg->prev_key, sizeof(cfg->prev_key));
    cfg->prev_key_len = 0;
    cfg->prev_key_id = 0;
    cfg->key_state = MWAN_PQC_KEY_STABLE;
    pr_info("mwan_kmod: PQC-REKEY RETIRED node=%u epoch=%llu current=%u\n",
            node_id, epoch, cfg->key_id);
out:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_abort_pqc_key(u32 node_id, u32 generation, u64 epoch,
                             u8 key_id)
{
    struct mwan_config *cfg;
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
    ret = mwan_l2_workers_abort_next_key(cfg, key_id);
    if (ret)
        goto out;
    memzero_explicit(cfg->next_key, sizeof(cfg->next_key));
    cfg->next_key_len = 0;
    cfg->next_key_id = 0;
    cfg->next_key_valid = false;
    cfg->rekey_epoch = 0;
    cfg->key_state = cfg->prev_key_valid ?
        MWAN_PQC_KEY_ACTIVE_WITH_PREV : MWAN_PQC_KEY_STABLE;
    pr_info("mwan_kmod: PQC-REKEY ABORTED node=%u epoch=%llu current=%u\n",
            node_id, epoch, cfg->key_id);
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
