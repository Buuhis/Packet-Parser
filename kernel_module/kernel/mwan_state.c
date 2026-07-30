#include "mwan_state.h"
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <linux/err.h>
#include <net/rtnetlink.h>

/* Global Configuration Pointer (RCU Protected) */
struct mwan_config __rcu *g_mwan_cfg = NULL;

/* Spinlock to protect concurrent updates to the configuration */
static DEFINE_SPINLOCK(cfg_lock);

/* Internal helper to free config and release device references */
static void mwan_config_free_rcu(struct rcu_head *rcu) {
    struct mwan_config *cfg = container_of(rcu, struct mwan_config, rcu);
    int i;

    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].dev) {
            dev_put(cfg->tunnels[i].dev);
        }
    }

    if (cfg->local_dev) {
        dev_put(cfg->local_dev);
    }
    if (cfg->tfm) {
        crypto_free_aead(cfg->tfm);
    }
    if (cfg->tx_wq) {
        destroy_workqueue(cfg->tx_wq);
    }
    for (i = 0; i < MWAN_REORDER_RING_SIZE; i++) {
        if (cfg->rx_reorder.ring[i]) {
            kfree_skb(cfg->rx_reorder.ring[i]);
            cfg->rx_reorder.ring[i] = NULL;
        }
    }
    kfree(cfg);
}

void mwan_state_init(void) {
    /* Optional: allocate an initial empty config if needed */
}

void mwan_state_cleanup(void) {
    struct mwan_config *old;
    
    spin_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    if (old) {
        RCU_INIT_POINTER(g_mwan_cfg, NULL);
        call_rcu(&old->rcu, mwan_config_free_rcu);
    }
    spin_unlock(&cfg_lock);
}

int mwan_state_update(struct mwan_config *new_cfg) {
    struct mwan_config *old;
    int i;
    
    if (!new_cfg) return -EINVAL;
    
    /* Phase 0: Resolve Local Network Interface */
    if (new_cfg->local_ifindex > 0) {
        new_cfg->local_dev = dev_get_by_index(&init_net, new_cfg->local_ifindex);
    }

    /* Phase 1: Pre-calculate and cache expensive data before publishing */
    new_cfg->total_weight = 0;
    for (i = 0; i < new_cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &new_cfg->tunnels[i];
        new_cfg->total_weight += tun->weight;

        /* Cache net_device */
        tun->dev = dev_get_by_index(&init_net, tun->ifindex);
        if (tun->dev) {
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
    if (new_cfg->encrypt_on && new_cfg->encrypt_key_len > 0) {
        struct crypto_aead *tfm;
        int err;

        /* Allocate hardware-accelerated RFC4106 AES-GCM driver */
        tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(tfm)) {
            pr_err("mwan_kmod: Failed to allocate AES-GCM transform: %ld\n", PTR_ERR(tfm));
            /* Cleanup and fail */
            for (i = 0; i < new_cfg->num_tunnels; i++) {
                if (new_cfg->tunnels[i].dev)
                    dev_put(new_cfg->tunnels[i].dev);
            }
            if (new_cfg->local_dev)
                dev_put(new_cfg->local_dev);
            return -ENOMEM;
        }

        /* RFC4106 requires crypto_aead_setkey to be called BEFORE crypto_aead_setauthsize!
         * Key buffer = 32B AES-256 Key + 4B Salt = 36 bytes total */
        u8 key_and_salt[MWAN_MAX_KEY_LEN + MWAN_SALT_LEN];
        memcpy(key_and_salt, new_cfg->encrypt_key, new_cfg->encrypt_key_len);
        memcpy(key_and_salt + new_cfg->encrypt_key_len, new_cfg->encrypt_salt, MWAN_SALT_LEN);
        err = crypto_aead_setkey(tfm, key_and_salt, new_cfg->encrypt_key_len + MWAN_SALT_LEN);
        if (err) {
            pr_err("mwan_kmod: Failed to set encryption key: %d\n", err);
            crypto_free_aead(tfm);
            for (i = 0; i < new_cfg->num_tunnels; i++) {
                if (new_cfg->tunnels[i].dev)
                    dev_put(new_cfg->tunnels[i].dev);
            }
            if (new_cfg->local_dev)
                dev_put(new_cfg->local_dev);
            return err;
        }

        err = crypto_aead_setauthsize(tfm, MWAN_GCM_TAG_LEN);
        if (err) {
            pr_err("mwan_kmod: Failed to set auth tag size: %d\n", err);
            crypto_free_aead(tfm);
            for (i = 0; i < new_cfg->num_tunnels; i++) {
                if (new_cfg->tunnels[i].dev)
                    dev_put(new_cfg->tunnels[i].dev);
            }
            if (new_cfg->local_dev)
                dev_put(new_cfg->local_dev);
            return err;
        }

        /* Calculate dynamic worker core count & reservation */
        int num_cpus = num_online_cpus();
        int worker_start = 0;
        int num_workers = num_cpus;
        if (num_cpus >= 8) {
            worker_start = 2; /* Reserve Core 0 & 1 for system/control plane */
            num_workers = num_cpus - 2;
        } else if (num_cpus >= 4) {
            worker_start = 1; /* Reserve Core 0 for system */
            num_workers = num_cpus - 1;
        }
        new_cfg->worker_start_cpu = worker_start;
        new_cfg->num_workers = num_workers;

        /* Allocate high-priority unbound workqueue for TX multi-core offload */
        new_cfg->tx_wq = alloc_workqueue("mwan_tx_wq", WQ_UNBOUND | WQ_HIGHPRI | WQ_CPU_INTENSIVE, 0);

        /* Initialize RX Reorder Ring Buffer */
        memset(new_cfg->rx_reorder.ring, 0, sizeof(new_cfg->rx_reorder.ring));
        atomic64_set(&new_cfg->rx_reorder.expected_seq, 1);
        spin_lock_init(&new_cfg->rx_reorder.drain_lock);

        new_cfg->tfm = tfm;
        atomic64_set(&new_cfg->encrypt_seq, 0);
        pr_info("mwan_kmod: AES-GCM crypto engine initialized (key_len=%u, workers=%d, start_cpu=%d)\n",
                new_cfg->encrypt_key_len, new_cfg->num_workers, new_cfg->worker_start_cpu);
    }

    /* Phase 2: Atomic update */
    spin_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    
    /* Safely publish the new configuration */
    rcu_assign_pointer(g_mwan_cfg, new_cfg);
    
    /* Defer the freeing of the old configuration */
    if (old) {
        call_rcu(&old->rcu, mwan_config_free_rcu);
    }
    spin_unlock(&cfg_lock);
    
    return 0;
}
