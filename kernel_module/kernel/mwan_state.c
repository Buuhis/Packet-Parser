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
            
            if (tun->dev->rtnl_link_ops && tun->dev->rtnl_link_ops->kind &&
                strcmp(tun->dev->rtnl_link_ops->kind, "macsec") == 0) {
                tun->encap_type = MWAN_ENCAP_MACSEC;
            } else if (new_cfg->encrypt_on) {
                tun->encap_type = MWAN_ENCAP_L3_CUSTOM;
            } else {
                tun->encap_type = MWAN_ENCAP_NONE;
            }
            
            {
                const char *encap_str = "NONE";
                if (tun->encap_type == MWAN_ENCAP_MACSEC) {
                    encap_str = "MACsec (L2)";
                } else if (tun->encap_type == MWAN_ENCAP_L3_CUSTOM) {
                    encap_str = "Custom L3 (AES-GCM)";
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
    }
    /* Phase 1.75: Initialize Crypto Engine if encryption is enabled */
    if (new_cfg->encrypt_on && new_cfg->encrypt_key_len > 0) {
        struct crypto_aead *tfm;
        int err;

        /* Force synchronous algorithm to avoid -EINPROGRESS in SoftIRQ/Netfilter hooks */
        tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(tfm)) {
            pr_err("mwan_kmod: Failed to allocate synchronous AES-GCM transform: %ld\n", PTR_ERR(tfm));
            /* Cleanup and fail */
            for (i = 0; i < new_cfg->num_tunnels; i++) {
                if (new_cfg->tunnels[i].dev)
                    dev_put(new_cfg->tunnels[i].dev);
            }
            if (new_cfg->local_dev)
                dev_put(new_cfg->local_dev);
            return -ENOMEM;
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

        err = crypto_aead_setkey(tfm, new_cfg->encrypt_key, new_cfg->encrypt_key_len);
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

        new_cfg->tfm = tfm;
        atomic64_set(&new_cfg->encrypt_seq, 0);
        pr_info("mwan_kmod: AES-GCM crypto engine initialized (key_len=%u)\n", new_cfg->encrypt_key_len);
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
