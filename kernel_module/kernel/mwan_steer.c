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

/* The core TX steering logic */
static unsigned int mwan_hook_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    int target_ifindex = 0;
    struct net_device *target_dev = NULL;
    
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

    /* 2. Hash: Compute 5-tuple hash to ensure flow affinity */
    {
        u32 ports = 0;
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            unsigned int offset = iph->ihl * 4;
            if (skb_headlen(skb) >= offset + 4) {
                ports = *(__be32 *)(skb_network_header(skb) + offset);
            }
        }
        hash = jhash_3words((__force u32)iph->saddr, (__force u32)iph->daddr, 
                            (iph->protocol << 16) | (ports & 0xFFFF), 0x12345678);
    }
    
    /* 3. Steer: Choose a tunnel based on the hash AND Weights */
    {
        u32 total_weight = 0;
        u32 target_slot = 0;
        int i;
        __be32 gateway = 0;
        
        for (i = 0; i < cfg->num_tunnels; i++) {
            total_weight += cfg->tunnels[i].weight;
        }

        if (total_weight > 0) {
            target_slot = hash % total_weight;
            u32 current_sum = 0;
            for (i = 0; i < cfg->num_tunnels; i++) {
                current_sum += cfg->tunnels[i].weight;
                if (target_slot < current_sum) {
                    target_ifindex = cfg->tunnels[i].ifindex;
                    gateway = cfg->tunnels[i].gateway;
                    break;
                }
            }
        }

        /* 4. Magic: Re-routing and Hardcode MAC */
        if (target_ifindex != 0) {
            target_dev = dev_get_by_index(state->net, target_ifindex);
            if (!target_dev) {
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            /* Prepare for L2 header manual construction */
            if (skb_headroom(skb) < ETH_HLEN) {
                struct sk_buff *new_skb = skb_realloc_headroom(skb, ETH_HLEN);
                if (!new_skb) {
                    dev_put(target_dev);
                    rcu_read_unlock();
                    return NF_ACCEPT; 
                }
                consume_skb(skb);
                skb = new_skb;
            }

            /* Build Ethernet Header */
            skb_push(skb, ETH_HLEN);
            skb_reset_mac_header(skb);
            {
                struct ethhdr *eth = eth_hdr(skb);
                /* 
                 * USER: Replace these with your actual simulation MACs 
                 * For example: Node 1 to Node 2 direct connection
                 */
                unsigned char hard_src[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x11, 0x22, 0x33}; // Placeholder
                unsigned char hard_dst[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x44, 0x55, 0x66}; // Placeholder

                if (target_dev->dev_addr) {
                    memcpy(eth->h_source, target_dev->dev_addr, ETH_ALEN);
                } else {
                    memcpy(eth->h_source, hard_src, ETH_ALEN);
                }
                memcpy(eth->h_dest, hard_dst, ETH_ALEN);
                eth->h_proto = htons(ETH_P_IP);

                /* FINAL LOG before sending to WAN */
                pr_info("mwan_kmod: [FINAL-OUT] dev: %s | src_mac: %pM | dst_mac: %pM | %pI4 -> %pI4\n",
                        target_dev->name, eth->h_source, eth->h_dest, &iph->saddr, &iph->daddr);
            }

            skb->dev = target_dev;
            dev_queue_xmit(skb);

            dev_put(target_dev);
            rcu_read_unlock();
            return NF_STOLEN; /* We handled the packet, don't let kernel continue */
        }
    }
    rcu_read_unlock();

    return NF_ACCEPT; 
}

/* Netfilter Hook Definition */
static struct nf_hook_ops mwan_nf_ops = {
    .hook     = mwan_hook_post_routing,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST, 
};

/* Hook Registration */
int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering POST_ROUTING steering hook\n");
    return nf_register_net_hook(&init_net, &mwan_nf_ops);
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hook\n");
    nf_unregister_net_hook(&init_net, &mwan_nf_ops);
}