#include "mwan_steer.h"
#include "mwan_state.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <net/dst.h>
#include <net/route.h>

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

    /* 2. Hash: Compute 5-tuple hash to ensure flow affinity
     * We include IP addresses, protocol, and Source/Dest Ports (if TCP/UDP)
     */
    {
        u32 ports = 0;
        /* TCP and UDP have Source and Dest ports in the same first 4 bytes */
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            unsigned int offset = iph->ihl * 4;
            /* Ensure we don't read past the linear buffer */
            if (skb_headlen(skb) >= offset + 4) {
                ports = *(__be32 *)(skb_network_header(skb) + offset);
            }
        }
        
        /* 
         * Combine addresses, protocol and ports into a fast hash.
         * Using jhash2 for arbitrary length, or just another 3words call.
         */
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

        /* 4. Magic: Re-routing to fix Egress Device AND L2 (MAC)
         * Changing skb->dev alone is not enough, we must update the routing cache (dst_entry)
         */
        if (target_ifindex != 0) {
            struct flowi4 fl4 = {
                .daddr = gateway ? gateway : iph->daddr,
                .saddr = 0, 
                .flowi4_oif = target_ifindex,
                .flowi4_tos = RT_TOS(iph->tos),
                .flowi4_proto = iph->protocol,
                .flowi4_mark = skb->mark,
            };
            struct rtable *rt;

            /* Lấy target_dev để verify interface tồn tại */
            target_dev = dev_get_by_index(state->net, target_ifindex);
            if (!target_dev) {
                pr_warn_ratelimited("mwan_kmod: Target ifindex %u not found\n", target_ifindex);
                goto out_unlock;
            }

            /* Tra cứu route trên namespace của hook state */
            rt = ip_route_output_key(state->net, &fl4);
            if (!IS_ERR(rt)) {
                skb_dst_drop(skb);
                skb_dst_set(skb, &rt->dst);
                skb->dev = rt->dst.dev;
                skb_clear_hash(skb);
                
                pr_debug("mwan_kmod: Forced steer %pI4 -> %pI4 via %s (gw: %pI4)\n",
                         &iph->saddr, &iph->daddr, skb->dev->name, &gateway);
            } else {
                pr_warn_ratelimited("mwan_kmod: Failed route to gateway %pI4 on ifindex %u\n",
                                    &gateway, target_ifindex);
            }
            dev_put(target_dev);
        }
out_unlock:
    }
    rcu_read_unlock();

    return NF_ACCEPT; 
}

/* Netfilter Hook Definition */
static struct nf_hook_ops mwan_nf_ops = {
    .hook     = mwan_hook_post_routing,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST, /* Run after iptables / nftables */
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
