#include "mwan_steer.h"
#include "mwan_state.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/neighbour.h>
#include <net/arp.h>

static bool is_mwan_tunnel(struct mwan_config *cfg, u32 ifindex)
{
    int i;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex)
            return true;
    }
    return false;
}

/* The core TX steering logic */
static unsigned int mwan_hook_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    
    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    
    if (!cfg || cfg->num_tunnels == 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Filter: Check if Destination IP matches our Overlay CIDR */
    if ((iph->daddr & cfg->cidr_mask) != (cfg->cidr_ip & cfg->cidr_mask)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 2. Hash: Use kernel-cached or hardware RSS hash for flow affinity */
    hash = skb_get_hash(skb);
    
    /* 3. Steer: Choose a tunnel based on the weight-proportional LUT (O(1)) */
    if (cfg->total_weight > 0 && cfg->num_tunnels > 0) {
        u8 tun_idx = cfg->tunnel_idx_lut[hash & (MWAN_LUT_SIZE - 1)];
        struct mwan_tunnel *tun = &cfg->tunnels[tun_idx];
        
        unsigned int ret = NF_ACCEPT;
        
        switch (tun->encap_type) {
            case MWAN_ENCAP_NONE:
                ret = mwan_handle_encap_none(skb, tun);
                break;
            case MWAN_ENCAP_MACSEC:
                ret = mwan_handle_encap_macsec(skb, tun);
                break;
            case MWAN_ENCAP_L3_CUSTOM:
                ret = mwan_handle_encap_l3(skb, tun);
                break;
            default:
                ret = mwan_handle_encap_none(skb, tun);
                break;
        }
        
        rcu_read_unlock();
        return ret;
    }


    rcu_read_unlock();
    return NF_ACCEPT; 
}

/* The core Inbound processing logic */
static unsigned int mwan_hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;

    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);

    if (!cfg || !cfg->local_dev) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Check if packet is coming from one of our WAN tunnels */
    if (is_mwan_tunnel(cfg, skb->dev->ifindex)) {
        /* 2. Check if Destination IP matches our Local CIDR */
        if ((iph->daddr & cfg->local_mask) == (cfg->local_ip & cfg->local_mask)) {
            /* 3. Steering: Route to Local Interface */
            
            /* We let the kernel handle the L2 (ARP/MAC) for the client 
             * because the user preferred the kernel to handle it. */
            /* Debug log: Capture info BEFORE switching device */
            if (skb->dev) {
                struct iphdr *iph_dbg = ip_hdr(skb);
                u16 frag_off = ntohs(iph_dbg->frag_off);
                bool is_frag = (frag_off & IP_MF) || (frag_off & IP_OFFSET);

                pr_info_ratelimited("mwan_kmod: INBOUND [CPU %u] from %s (RXQ: %u) Proto: %u Frag: %s -> To %s\n",
                                    smp_processor_id(),
                                    skb->dev->name, 
                                    skb_rx_queue_recorded(skb) ? skb_get_rx_queue(skb) : 0,
                                    iph_dbg->protocol,
                                    is_frag ? "YES" : "NO",
                                    cfg->local_dev->name);
            }

            skb->dev = cfg->local_dev;
            
            /* Important: Clear any stale L2 header remains to avoid corruption */
            skb_pull(skb, skb_network_offset(skb));
            skb_reset_mac_header(skb);

            /* We return NF_ACCEPT to let the kernel finish routing/delivery locally 
             * to the destination client, now that we've set the correct skb->dev. */
        }
    }

    rcu_read_unlock();
    return NF_ACCEPT;
}

/* Netfilter Hook Definitions */
static struct nf_hook_ops mwan_nf_ops[] = {
    {
        .hook     = mwan_hook_post_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_LAST, 
    },
    {
        .hook     = mwan_hook_pre_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST, 
    },
};

/* Hook Registration */
int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering Netfilter steering hooks\n");
    return nf_register_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hooks\n");
    nf_unregister_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}
