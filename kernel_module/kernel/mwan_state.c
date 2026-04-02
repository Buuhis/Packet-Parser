#include "mwan_state.h"
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/neighbour.h>
#include <net/arp.h>

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
            tun->is_ethernet = (tun->dev->type == ARPHRD_ETHER);
            
            /* Attempt to resolve MAC if it's an ethernet device */
            if (tun->is_ethernet && tun->gateway) {
                struct neighbour *n;
                n = neigh_lookup(&arp_tbl, &tun->gateway, tun->dev);
                if (n) {
                    if (n->nud_state & NUD_VALID) {
                        read_lock_bh(&n->lock);
                        memcpy(tun->gateway_mac, n->ha, 6);
                        read_unlock_bh(&n->lock);
                        tun->mac_resolved = true;
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
