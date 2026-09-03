#include "mwan_state.h"
#include "mwan_mac_discovery.h"
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/random.h>
#include <linux/err.h>
#include <net/rtnetlink.h>

/* Global Configuration Pointer (RCU Protected) */
struct mwan_config __rcu *g_mwan_cfg = NULL;

/* Configuration updates run from Generic Netlink process context and may
 * sleep while waiting for an RCU grace period and shutting down timers. */
DEFINE_MUTEX(mwan_cfg_update_lock);

/* Keep the packet nonce outside mwan_config so pushing the same config again
 * cannot reuse an AES-GCM IV while the active key is unchanged. L2 and L3
 * share this monotonic source. */
static atomic64_t packet_nonce;
static atomic64_t no_active_tunnel_drops;

static struct mwan_active_paths *
mwan_active_paths_build(const struct mwan_config *cfg)
{
    struct mwan_active_paths *paths;
    int last_active = -1;
    u32 current_slot = 0;
    u32 i;

    paths = kzalloc(sizeof(*paths), GFP_KERNEL);
    if (!paths)
        return NULL;

    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];

        if (!tun->published_up)
            continue;
        paths->active_count++;
        paths->total_weight += tun->weight;
        last_active = (int)i;
    }

    if (paths->active_count == 0 || paths->total_weight == 0)
        return paths;

    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];
        u32 count;
        u32 j;

        if (!tun->published_up)
            continue;
        count = (u32)(((u64)tun->weight * MWAN_LUT_SIZE) /
                      paths->total_weight);
        for (j = 0; j < count && current_slot < MWAN_LUT_SIZE; j++)
            paths->tunnel_idx_lut[current_slot++] = (u8)i;
    }
    while (current_slot < MWAN_LUT_SIZE)
        paths->tunnel_idx_lut[current_slot++] = (u8)last_active;

    return paths;
}

static void mwan_config_release_devices(struct mwan_config *cfg)
{
    int i;

    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].dev) {
            dev_put(cfg->tunnels[i].dev);
            cfg->tunnels[i].dev = NULL;
        }
    }

}

static void mwan_config_preserve_peer_state(struct mwan_config *new_cfg,
                                            struct mwan_config *old_cfg)
{
    u32 i;
    u32 j;

    if (!new_cfg || !old_cfg)
        return;

    for (i = 0; i < new_cfg->num_tunnels; i++) {
        struct mwan_tunnel *new_tun = &new_cfg->tunnels[i];

        for (j = 0; j < old_cfg->num_tunnels; j++) {
            struct mwan_tunnel *old_tun = &old_cfg->tunnels[j];

            if (new_tun->configured_ifindex !=
                old_tun->configured_ifindex)
                continue;
            spin_lock_bh(&old_tun->gateway_mac_lock);
            if (old_tun->mac_resolved &&
                is_valid_ether_addr(old_tun->gateway_mac)) {
                spin_lock_bh(&new_tun->gateway_mac_lock);
                ether_addr_copy(new_tun->gateway_mac,
                                old_tun->gateway_mac);
                new_tun->mac_resolved = true;
                new_tun->peer_tunnel_ip = old_tun->peer_tunnel_ip;
                new_tun->peer_ip_resolved =
                    old_tun->peer_ip_resolved;
                new_tun->discovery_nonce = old_tun->discovery_nonce;
                spin_unlock_bh(&new_tun->gateway_mac_lock);
            }
            spin_unlock_bh(&old_tun->gateway_mac_lock);
            new_tun->published_up = old_tun->published_up;
            /* State sequences are scoped to one full-config generation. */
            new_tun->state_sequence = 0;
            break;
        }
    }
}

/* Destroy only a config that has been published. The caller first waits for
 * all RCU readers; flow-manager shutdown then blocks timer rearming before
 * synchronously deleting each per-flow timer (including on kernel 5.19). */
static void mwan_config_destroy(struct mwan_config *cfg)
{
    struct mwan_active_paths *paths;

    if (!cfg)
        return;

    paths = rcu_dereference_protected(cfg->active_paths, 1);
    RCU_INIT_POINTER(cfg->active_paths, NULL);
    kfree(paths);

    /* No RCU reader can enqueue into this config now. Drain worker-owned
     * references first, then destroy the per-connection flow tables/timers. */
    mwan_l2_workers_cleanup(cfg);
    mwan_l2_flow_manager_stop(cfg);

    if (cfg->tfm) {
        crypto_free_aead(cfg->tfm);
        cfg->tfm = NULL;
    }
    if (cfg->prev_tfm) {
        crypto_free_aead(cfg->prev_tfm);
        cfg->prev_tfm = NULL;
    }

    mwan_config_release_devices(cfg);
    kvfree_sensitive(cfg, sizeof(*cfg));
}

void mwan_state_init(void)
{
    BUILD_BUG_ON(sizeof(struct mwan_l2_pqc_hdr) != MWAN_L2_HDR_LEN);
    atomic64_set(&packet_nonce, get_random_u64());
    atomic64_set(&no_active_tunnel_drops, 0);
}

u64 mwan_next_packet_nonce(void)
{
    u64 nonce = (u64)atomic64_inc_return(&packet_nonce);

    /* A full 64-bit wrap is practically unreachable, but zero would prove
     * nonce reuse after a wrap and must never be used for encryption. */
    if (WARN_ON_ONCE(nonce == 0))
        return 0;

    return nonce;
}

void mwan_state_cleanup(void)
{
    struct mwan_config *old;

    mutex_lock(&mwan_cfg_update_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    if (old) {
        RCU_INIT_POINTER(g_mwan_cfg, NULL);
        synchronize_rcu();
        mwan_config_destroy(old);
    }
    mutex_unlock(&mwan_cfg_update_lock);
}

int mwan_state_update(struct mwan_config *new_cfg)
{
    struct mwan_config *old;
    struct mwan_active_paths *new_paths;
    struct crypto_aead *tfm = NULL;
    struct crypto_aead *prev_tfm = NULL;
    int i, err = 0;

    if (!new_cfg)
        return -EINVAL;

    if (new_cfg->num_tunnels > MAX_MWAN_TUNNELS)
        return -E2BIG;

    if (new_cfg->encrypt_on) {
        if (new_cfg->encrypt_layer != 2 && new_cfg->encrypt_layer != 3) {
            pr_err("mwan_kmod: Invalid encryption layer %u\n",
                   new_cfg->encrypt_layer);
            return -EINVAL;
        }
        if (new_cfg->encrypt_type > MWAN_CRYPT_PQC_GCM) {
            pr_err("mwan_kmod: Invalid encryption type %u\n",
                   new_cfg->encrypt_type);
            return -EINVAL;
        }
        if (new_cfg->encrypt_key_len != 16 &&
            new_cfg->encrypt_key_len != 32) {
            pr_err("mwan_kmod: Invalid AES key length %u (expected 16 or 32)\n",
                   new_cfg->encrypt_key_len);
            return -EINVAL;
        }
        if ((new_cfg->encrypt_type == MWAN_CRYPT_AES_GCM_128 &&
             new_cfg->encrypt_key_len != 16) ||
            (new_cfg->encrypt_type != MWAN_CRYPT_AES_GCM_128 &&
             new_cfg->encrypt_key_len != 32)) {
            pr_err("mwan_kmod: Encryption type %u does not match key length %u\n",
                   new_cfg->encrypt_type, new_cfg->encrypt_key_len);
            return -EINVAL;
        }
    }

    if (new_cfg->key_id == 0)
        new_cfg->key_id = 1;
    new_cfg->next_key_id = 0;
    new_cfg->next_key_len = 0;
    new_cfg->next_key_valid = false;
    new_cfg->rekey_epoch = 0;
    new_cfg->key_state = new_cfg->prev_key_valid ?
        MWAN_PQC_KEY_ACTIVE_WITH_PREV : MWAN_PQC_KEY_STABLE;
    mwan_rekey_diag_init(new_cfg);
    err = mwan_l2_flow_manager_init(new_cfg);
    if (err)
        return err;

    /* Phase 1: Pre-calculate and cache expensive data before publishing */
    new_cfg->total_weight = 0;
    for (i = 0; i < new_cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &new_cfg->tunnels[i];

        if (tun->configured_ifindex == 0)
            tun->configured_ifindex = tun->ifindex;
        spin_lock_init(&tun->gateway_mac_lock);
        eth_zero_addr(tun->gateway_mac);
        tun->mac_resolved = false;
        tun->peer_tunnel_ip = 0;
        tun->discovery_nonce = 0;
        tun->peer_ip_resolved = false;
        if (U32_MAX - new_cfg->total_weight < tun->weight) {
            pr_err("mwan_kmod: Tunnel weight sum overflow\n");
            err = -EOVERFLOW;
            goto err_release_devices;
        }
        new_cfg->total_weight += tun->weight;

        /* Cache net_device */
        tun->dev = dev_get_by_index(&init_net, tun->ifindex);
        if (!tun->dev) {
            pr_err("mwan_kmod: Tunnel ifindex %u does not exist\n", tun->ifindex);
            err = -ENODEV;
            goto err_release_devices;
        }
        {
            struct net_device *upper_dev;
            struct list_head *iter;
            struct net_device *macsec_dev = NULL;

            /* Check if there is an upper MACsec device stacked on top of this device */
            rcu_read_lock();
            netdev_for_each_upper_dev_rcu(tun->dev, upper_dev, iter) {
                if (upper_dev->rtnl_link_ops && upper_dev->rtnl_link_ops->kind &&
                    strcmp(upper_dev->rtnl_link_ops->kind, "macsec") == 0) {
                    macsec_dev = upper_dev;
                    dev_hold(macsec_dev);
                    break;
                }
            }
            rcu_read_unlock();

            if (macsec_dev) {
                /* Replace tun->dev with the MACsec device */
                dev_put(tun->dev);
                tun->dev = macsec_dev;
                tun->ifindex = macsec_dev->ifindex;
            }

            tun->is_ethernet = (tun->dev->type == ARPHRD_ETHER);
            
            if (new_cfg->encrypt_on) {
                if (new_cfg->encrypt_layer == 2) {
                    if (new_cfg->encrypt_type == MWAN_CRYPT_PQC_GCM) {
                        tun->encap_type = MWAN_ENCAP_L2_PQC;
                    } else {
                        tun->encap_type = MWAN_ENCAP_MACSEC;
                    }
                } else if (new_cfg->encrypt_layer == 3 &&
                           new_cfg->encrypt_type == MWAN_CRYPT_PQC_GCM) {
                    tun->encap_type = MWAN_ENCAP_L3_PQC;
                } else if (new_cfg->encrypt_layer == 3) {
                    tun->encap_type = MWAN_ENCAP_L3_CUSTOM;
                } else {
                    tun->encap_type = MWAN_ENCAP_NONE;
                }
            } else {
                tun->encap_type = MWAN_ENCAP_NONE;
            }
            
            {
                const char *encap_str = "NONE";
                if (tun->encap_type == MWAN_ENCAP_MACSEC) {
                    encap_str = "MACsec (L2)";
                } else if (tun->encap_type == MWAN_ENCAP_L2_PQC) {
                    encap_str = "L2 PQC (AES-GCM + PQC session key)";
                } else if (tun->encap_type == MWAN_ENCAP_L3_CUSTOM) {
                    encap_str = "Custom L3 (AES-GCM static key)";
                } else if (tun->encap_type == MWAN_ENCAP_L3_PQC) {
                    encap_str = "L3 PQC (AES-GCM + PQC session key)";
                }
                pr_info("mwan_kmod: Resolved tunnel interface %s (ifindex %d) - Encap Type: %s\n",
                        tun->dev->name, tun->ifindex, encap_str);
            }
            
        }
    }

    /* Phase 1.5: Populate weight-proportional LUT for O(1) steering */
    if (new_cfg->total_weight > 0 && new_cfg->num_tunnels > 0) {
        int current_slot = 0;
        for (i = 0; i < new_cfg->num_tunnels; i++) {
            int count = (new_cfg->tunnels[i].weight * MWAN_LUT_SIZE) / new_cfg->total_weight;
            int j;
            for (j = 0; j < count && current_slot < MWAN_LUT_SIZE; j++) {
                new_cfg->tunnel_idx_lut[current_slot++] = i;
            }
        }
        /* Handle rounding: ensure remaining slots are filled */
        while (current_slot < MWAN_LUT_SIZE) {
            new_cfg->tunnel_idx_lut[current_slot++] = new_cfg->num_tunnels - 1;
        }

        pr_info("mwan_kmod: Config updated - num_tunnels: %u, total_weight: %u\n", 
                new_cfg->num_tunnels, new_cfg->total_weight);
        for (i = 0; i < new_cfg->num_tunnels; i++) {
            struct mwan_tunnel *t = &new_cfg->tunnels[i];
            pr_info("  [Tunnel %d] name: %s, ifindex: %u, weight: %u, dev_ptr: %px\n",
                    i, t->dev ? t->dev->name : "NULL", t->ifindex,
                    t->weight, t->dev);
        }
    }
    /* Phase 1.75: Initialize Crypto Engine if encryption is enabled */
    if (new_cfg->encrypt_on) {
        u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];

        /* Allocate hardware-accelerated RFC4106 AES-GCM driver */
        tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(tfm)) {
            err = PTR_ERR(tfm);
            pr_err("mwan_kmod: Failed to allocate AES-GCM transform: %d\n", err);
            goto err_release_devices;
        }

        if (crypto_aead_ivsize(tfm) != MWAN_RFC4106_IV_LEN) {
            pr_err("mwan_kmod: Unexpected RFC4106 IV size %u\n",
                   crypto_aead_ivsize(tfm));
            err = -EINVAL;
            goto err_free_tfm;
        }

        /* RFC4106 requires crypto_aead_setkey to be called BEFORE crypto_aead_setauthsize!
         * Key buffer = 32B AES-256 Key + 4B Salt = 36 bytes total */
        memcpy(key_and_salt, new_cfg->encrypt_key, new_cfg->encrypt_key_len);
        memcpy(key_and_salt + new_cfg->encrypt_key_len, new_cfg->encrypt_salt, MWAN_SALT_LEN);
        err = crypto_aead_setkey(tfm, key_and_salt, new_cfg->encrypt_key_len + MWAN_SALT_LEN);
        memzero_explicit(key_and_salt, sizeof(key_and_salt));
        if (err) {
            pr_err("mwan_kmod: Failed to set encryption key: %d\n", err);
            goto err_free_tfm;
        }

        err = crypto_aead_setauthsize(tfm, MWAN_GCM_TAG_LEN);
        if (err) {
            pr_err("mwan_kmod: Failed to set auth tag size: %d\n", err);
            goto err_free_tfm;
        }

        if (new_cfg->prev_key_valid) {
            prev_tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0,
                                         CRYPTO_ALG_ASYNC);
            if (IS_ERR(prev_tfm)) {
                err = PTR_ERR(prev_tfm);
                prev_tfm = NULL;
                goto err_free_tfm;
            }
            if (crypto_aead_ivsize(prev_tfm) != MWAN_RFC4106_IV_LEN) {
                err = -EINVAL;
                goto err_free_tfm;
            }
            memcpy(key_and_salt, new_cfg->prev_key,
                   new_cfg->prev_key_len);
            memcpy(key_and_salt + new_cfg->prev_key_len,
                   new_cfg->encrypt_salt, MWAN_SALT_LEN);
            err = crypto_aead_setkey(prev_tfm, key_and_salt,
                                     new_cfg->prev_key_len + MWAN_SALT_LEN);
            memzero_explicit(key_and_salt, sizeof(key_and_salt));
            if (err)
                goto err_free_tfm;
            err = crypto_aead_setauthsize(prev_tfm, MWAN_GCM_TAG_LEN);
            if (err)
                goto err_free_tfm;
            new_cfg->prev_tfm = prev_tfm;
        }

        new_cfg->tfm = tfm;
        pr_info("mwan_kmod: AES-GCM crypto engine initialized (key_len=%u)\n",
                new_cfg->encrypt_key_len);

    }

    /* Bypass and L2-PQC share the sticky per-flow TX dispatcher.  Other
     * encryption modes retain their existing synchronous datapaths. */
    err = mwan_l2_workers_init(new_cfg);
    if (err)
        goto err_free_tfm;

    /* Phase 2: publish, wait for old readers, stop the old timer and destroy
     * the old config in this process context. No RCU callback survives module
     * unload, and no blocking operation runs from softirq context. */
    mutex_lock(&mwan_cfg_update_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    if (old) {
        pr_info("mwan_kmod: CFG-TRACE REPLACE old=%u/%u/%u/%u new=%u/%u/%u/%u\n",
                old->node_id, old->encrypt_on, old->encrypt_layer,
                old->encrypt_type, new_cfg->node_id,
                new_cfg->encrypt_on, new_cfg->encrypt_layer,
                new_cfg->encrypt_type);
    } else {
        pr_info("mwan_kmod: CFG-TRACE INITIAL node=%u mode=%u/%u/%u\n",
                new_cfg->node_id, new_cfg->encrypt_on,
                new_cfg->encrypt_layer, new_cfg->encrypt_type);
    }
    /* Netlink updates (for example PQC key rotation) replace the whole
     * config. Preserve the independently learned MAC/IP tuple for an
     * unchanged data tunnel so traffic and failover do not rediscover it. */
    mwan_config_preserve_peer_state(new_cfg, old);
    new_paths = mwan_active_paths_build(new_cfg);
    if (!new_paths) {
        mutex_unlock(&mwan_cfg_update_lock);
        err = -ENOMEM;
        goto err_free_tfm;
    }
    RCU_INIT_POINTER(new_cfg->active_paths, new_paths);
    rcu_assign_pointer(g_mwan_cfg, new_cfg);
    synchronize_rcu();
    mwan_config_destroy(old);
    pr_info("mwan_kmod: CFG-TRACE ACTIVE node=%u mode=%u/%u/%u tunnels=%u\n",
            new_cfg->node_id, new_cfg->encrypt_on,
            new_cfg->encrypt_layer, new_cfg->encrypt_type,
            new_cfg->num_tunnels);
    mutex_unlock(&mwan_cfg_update_lock);

    mwan_l2_flow_manager_start(new_cfg);
    /* Resolve one independent peer MAC/IP tuple for every bonding tunnel. */
    mwan_mac_discovery_kick();

    return 0;

err_free_tfm:
    mwan_l2_workers_cleanup(new_cfg);
    if (prev_tfm)
        crypto_free_aead(prev_tfm);
    if (tfm)
        crypto_free_aead(tfm);
err_release_devices:
    mwan_l2_flow_manager_stop(new_cfg);
    mwan_config_release_devices(new_cfg);
    return err;
}

int mwan_state_set_tunnel_state(u32 ifindex, u32 generation,
                                u32 sequence, bool up)
{
    struct mwan_active_paths *new_paths;
    struct mwan_active_paths *old_paths;
    struct mwan_config *cfg;
    struct mwan_tunnel *tun = NULL;
    bool old_up;
    u32 i;
    int ret = 0;

    if (ifindex == 0 || generation == 0 || sequence == 0)
        return -EINVAL;

    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(g_mwan_cfg,
                                    lockdep_is_held(&mwan_cfg_update_lock));
    if (!cfg) {
        ret = -ENOENT;
        goto out_unlock;
    }
    if (cfg->generation != generation) {
        ret = -ESTALE;
        goto out_unlock;
    }
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].configured_ifindex == ifindex ||
            cfg->tunnels[i].ifindex == ifindex) {
            tun = &cfg->tunnels[i];
            break;
        }
    }
    if (!tun) {
        ret = -ENOENT;
        goto out_unlock;
    }
    if (sequence < tun->state_sequence ||
        (sequence == tun->state_sequence && tun->published_up != up)) {
        ret = -ESTALE;
        goto out_unlock;
    }
    if (sequence == tun->state_sequence && tun->published_up == up)
        goto out_unlock;
    if (tun->published_up == up) {
        tun->state_sequence = sequence;
        goto out_unlock;
    }

    old_up = tun->published_up;
    tun->published_up = up;
    new_paths = mwan_active_paths_build(cfg);
    if (!new_paths) {
        tun->published_up = old_up;
        ret = -ENOMEM;
        goto out_unlock;
    }
    tun->state_sequence = sequence;
    old_paths = rcu_dereference_protected(cfg->active_paths,
                                          lockdep_is_held(&mwan_cfg_update_lock));
    rcu_assign_pointer(cfg->active_paths, new_paths);
    synchronize_rcu();
    kfree(old_paths);

    pr_info("mwan_kmod: BFD-STATE ifindex=%u %s->%s active=%u\n",
            ifindex, old_up ? "UP" : "DOWN", up ? "UP" : "DOWN",
            new_paths->active_count);

out_unlock:
    mutex_unlock(&mwan_cfg_update_lock);
    return ret;
}

int mwan_state_get_tunnel_state(u32 ifindex, u32 *generation,
                                u32 *sequence, bool *up)
{
    struct mwan_config *cfg;
    u32 i;
    int ret = -ENOENT;

    if (ifindex == 0 || !generation || !sequence || !up)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg)
        goto out;
    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];

        if (tun->configured_ifindex != ifindex && tun->ifindex != ifindex)
            continue;
        *generation = cfg->generation;
        *sequence = READ_ONCE(tun->state_sequence);
        *up = READ_ONCE(tun->published_up);
        ret = 0;
        break;
    }
out:
    rcu_read_unlock();
    return ret;
}

void mwan_state_count_no_active_drop(void)
{
    atomic64_inc(&no_active_tunnel_drops);
}

u64 mwan_state_no_active_drops(void)
{
    return (u64)atomic64_read(&no_active_tunnel_drops);
}
