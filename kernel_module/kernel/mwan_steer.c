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

/* The core RX/Forwarding steering logic */
static unsigned int mwan_hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash;
    
    if (!skb) return NF_ACCEPT;
    
    /* PRE_ROUTING hook: skb->data points to IP header, but MAC header is available */
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

    /* 2. Hash: Leverage hardware hash or previously computed kernel hash */
    hash = skb_get_hash(skb);
    
    /* 3. Steer: Choose a tunnel based on the hash AND Weights */
    if (cfg->total_weight > 0) {
        u32 target_slot = hash % cfg->total_weight;
        u32 current_sum = 0;
        int i;

        for (i = 0; i < cfg->num_tunnels; i++) {
            struct mwan_tunnel *tun = &cfg->tunnels[i];
            current_sum += tun->weight;

            if (target_slot < current_sum) {
                struct net_device *target_dev = tun->dev;
                
                if (unlikely(!target_dev)) break;

                /* 4. Transformation: Zero-copy redirection */
                
                if (tun->is_ethernet) {
                    if (unlikely(!tun->mac_resolved)) break;

                    /* Zero-Copy "MAC Swap": Reuse existing MAC header area.
                     * We only cow_head if the header is shared to avoid hosing other readers. */
                    if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev))) break;

                    /* Correct pointers after possible cow */
                    iph = ip_hdr(skb);
                    
                    /* Pointer to existing MAC header */
                    struct ethhdr *eth = eth_hdr(skb);
                    if (unlikely(!eth)) break;

                    /* Update Source MAC from Target Device */
                    if (target_dev->dev_addr)
                        memcpy(eth->h_source, target_dev->dev_addr, ETH_ALEN);
                    
                    /* Update Destination MAC from Gateway Cache */
                    memcpy(eth->h_dest, tun->gateway_mac, ETH_ALEN);
                    eth->h_proto = htons(ETH_P_IP);

                    /* Bring skb->data back to the MAC header for dev_queue_xmit */
                    skb_push(skb, skb_network_offset(skb));
                } else {
                    /* Non-ethernet device (Point-to-Point) 
                     * Ensure skb->data is at network header and metadata is clean */
                    skb_reset_mac_header(skb);
                }

                /* Final Egress */
                skb->dev = target_dev;
                
                /* Decrement TTL as we are bypassing the standard forwarding path */
                iph = ip_hdr(skb);
                ip_decrease_ttl(iph);

                dev_queue_xmit(skb);

                rcu_read_unlock();
                return NF_STOLEN;
            }
        }
    }
    
    rcu_read_unlock();
    return NF_ACCEPT; 
}

/* Netfilter Hook Definition */
static struct nf_hook_ops mwan_nf_ops = {
    .hook     = mwan_hook_pre_routing,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST, 
};

/* Hook Registration */
int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering PRE_ROUTING steering hook\n");
    return nf_register_net_hook(&init_net, &mwan_nf_ops);
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hook\n");
    nf_unregister_net_hook(&init_net, &mwan_nf_ops);
}