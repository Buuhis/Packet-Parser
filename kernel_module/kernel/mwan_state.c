#include "mwan_state.h"
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/random.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <linux/err.h>
#include <net/rtnetlink.h>

/* Global Configuration Pointer (RCU Protected) */
struct mwan_config __rcu *g_mwan_cfg = NULL;

/* Configuration updates run from Generic Netlink process context and may
 * sleep while waiting for an RCU grace period and shutting down timers. */
static DEFINE_MUTEX(cfg_lock);

/* Keep reorder sequences and the packet nonce outside mwan_config so pushing
 * the same config again cannot reset them while the active key is unchanged. */
static atomic64_t l2_tx_seq[MWAN_FLOW_TABLE_SIZE];
static atomic64_t l2_packet_nonce;

static void mwan_config_release_devices(struct mwan_config *cfg)
{
    int i;

    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].dev) {
            dev_put(cfg->tunnels[i].dev);
            cfg->tunnels[i].dev = NULL;
        }
    }

    if (cfg->local_dev) {
        dev_put(cfg->local_dev);
        cfg->local_dev = NULL;
    }
}

/* Destroy only a config that has been published. The caller must first wait
 * for all RCU readers; timer_shutdown_sync() then prevents timer rearming. */
static void mwan_config_destroy(struct mwan_config *cfg)
{
    int i;

    if (!cfg)
        return;

    timer_shutdown_sync(&cfg->reorder_timer);

    for (i = 0; i < MWAN_FLOW_TABLE_SIZE; i++) {
        struct mwan_per_flow_reorder *flow = &cfg->flow_reorder[i];
        int j;

        for (j = 0; j < MWAN_FLOW_RING_SIZE; j++) {
            if (flow->ring[j]) {
                kfree_skb(flow->ring[j]);
                flow->ring[j] = NULL;
            }
        }
    }

    if (cfg->tfm) {
        crypto_free_aead(cfg->tfm);
        cfg->tfm = NULL;
    }

    mwan_config_release_devices(cfg);
    kvfree_sensitive(cfg, sizeof(*cfg));
}

void mwan_state_init(void)
{
    int i;

    BUILD_BUG_ON(sizeof(struct mwan_l2_pqc_hdr) != MWAN_L2_HDR_LEN);

    for (i = 0; i < MWAN_FLOW_TABLE_SIZE; i++)
        atomic64_set(&l2_tx_seq[i], 0);
    atomic64_set(&l2_packet_nonce, get_random_u64());
}

u64 mwan_l2_next_tx_seq(u32 flow_idx)
{
    if (WARN_ON_ONCE(flow_idx >= MWAN_FLOW_TABLE_SIZE))
        flow_idx = 0;

    return (u64)atomic64_inc_return(&l2_tx_seq[flow_idx]);
}

u64 mwan_l2_next_packet_nonce(void)
{
    u64 nonce = (u64)atomic64_inc_return(&l2_packet_nonce);

    /* A full 64-bit wrap is practically unreachable, but zero would prove
     * nonce reuse after a wrap and must never be used for encryption. */
    if (WARN_ON_ONCE(nonce == 0))
        return 0;

    return nonce;
}

void mwan_state_cleanup(void)
{
    struct mwan_config *old;

    mutex_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    if (old) {
        RCU_INIT_POINTER(g_mwan_cfg, NULL);
        synchronize_rcu();
        mwan_config_destroy(old);
    }
    mutex_unlock(&cfg_lock);
}

int mwan_state_update(struct mwan_config *new_cfg)
{
    struct mwan_config *old;
    struct crypto_aead *tfm = NULL;
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
    }

    /* Initialize this for every publishable config. Destruction can therefore
     * always use timer_shutdown_sync(), even when encryption is disabled. */
    timer_setup(&new_cfg->reorder_timer, mwan_reorder_timeout, 0);
    for (i = 0; i < MWAN_FLOW_TABLE_SIZE; i++) {
        atomic64_set(&new_cfg->flow_reorder[i].expected_seq, 1);
        spin_lock_init(&new_cfg->flow_reorder[i].drain_lock);
    }

    /* Phase 0: Resolve Local Network Interface */
    if (new_cfg->local_ifindex > 0) {
        new_cfg->local_dev = dev_get_by_index(&init_net, new_cfg->local_ifindex);
        if (!new_cfg->local_dev) {
            pr_err("mwan_kmod: Local ifindex %u does not exist\n",
                   new_cfg->local_ifindex);
            err = -ENODEV;
            goto err_release_devices;
        }
    }

    /* Phase 1: Pre-calculate and cache expensive data before publishing */
    new_cfg->total_weight = 0;
    for (i = 0; i < new_cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &new_cfg->tunnels[i];
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
            
            /* Attempt to resolve MAC if it's an ethernet device */
            if (tun->is_ethernet && tun->gateway) {
                struct neighbour *n;
                n = neigh_lookup(&arp_tbl, &tun->gateway, tun->dev);
                if (!n) {
                    /* Chủ động tạo ô trống nếu Linux lỡ quên */
                    n = neigh_create(&arp_tbl, &tun->gateway, tun->dev);
                }
                
                if (n && !IS_ERR(n)) {
                    if (n->nud_state & NUD_VALID) {
                        read_lock_bh(&n->lock);
                        memcpy(tun->gateway_mac, n->ha, 6);
                        read_unlock_bh(&n->lock);
                        tun->mac_resolved = true;
                    } else {
                        /* POKE Kernel: Bắn Ping Mồi ARP ngay lập tức để lấy MAC về cho Hot-path */
                        neigh_event_send(n, NULL);
                        tun->mac_resolved = false;
                    }
                    neigh_release(n);
                }
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
            pr_info("  [Tunnel %d] name: %s, ifindex: %u, weight: %u, mac_resolved: %d, dev_ptr: %px\n",
                    i, t->dev ? t->dev->name : "NULL", t->ifindex, t->weight, t->mac_resolved, t->dev);
        }
    }
    /* Phase 1.75: Initialize Crypto Engine if encryption is enabled */
    if (new_cfg->encrypt_on) {
        u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];
        int num_cpus = num_online_cpus();
        int worker_start = 0;
        int num_workers = num_cpus;

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

        /* Crypto runs inline on the CPU selected by RSS/RPS.  Advertise every
         * online CPU here; optional control-plane isolation is applied by the
         * userspace CPU tuner through SDWAN_RESERVED_CPUS. */
        new_cfg->worker_start_cpu = worker_start;
        new_cfg->num_workers = num_workers;

        new_cfg->tfm = tfm;
        atomic64_set(&new_cfg->encrypt_seq, 0);
        pr_info("mwan_kmod: AES-GCM crypto engine initialized (key_len=%u, workers=%d, start_cpu=%d)\n",
                new_cfg->encrypt_key_len, new_cfg->num_workers, new_cfg->worker_start_cpu);
    }

    /* Phase 2: publish, wait for old readers, stop the old timer and destroy
     * the old config in this process context. No RCU callback survives module
     * unload, and no blocking operation runs from softirq context. */
    mutex_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    rcu_assign_pointer(g_mwan_cfg, new_cfg);
    synchronize_rcu();
    mwan_config_destroy(old);
    mutex_unlock(&cfg_lock);

    return 0;

err_free_tfm:
    if (tfm)
        crypto_free_aead(tfm);
err_release_devices:
    timer_shutdown_sync(&new_cfg->reorder_timer);
    mwan_config_release_devices(new_cfg);
    return err;
}
