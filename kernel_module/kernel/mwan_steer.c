#include "mwan_steer.h"
#include "mwan_state.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/if_ether.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/neighbour.h>

/* Core steering logic used by both FORWARD and LOCAL_OUT */
static unsigned int mwan_do_steer(struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    int target_ifindex = 0;
    
    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    
    if (!cfg || cfg->num_tunnels == 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Filter Overlay CIDR */
    if ((iph->daddr & cfg->cidr_mask) != (cfg->cidr_ip & cfg->cidr_mask)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Compute Flow Hash */
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
    
    /* Selecting Tunnel */
    {
        u32 total_weight = 0;
        int i;
        __be32 gateway = 0;
        for (i = 0; i < cfg->num_tunnels; i++) total_weight += cfg->tunnels[i].weight;

        if (total_weight > 0) {
            u32 target_slot = hash % total_weight;
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

        /* Forward Re-routing Magic */
        if (target_ifindex != 0) {
            struct flowi4 fl4 = {
                .daddr = gateway ? gateway : iph->daddr,
                .saddr = 0, 
                .flowi4_oif = target_ifindex,
            };
            struct rtable *rt;

            rt = ip_route_output_key(state->net, &fl4);
            if (!IS_ERR(rt)) {
                if (rt->dst.error) {
                    ip_rt_put(rt);
                    goto out;
                }

                skb_dst_drop(skb);
                skb_dst_set(skb, &rt->dst);
                skb->dev = rt->dst.dev;
                skb_clear_hash(skb);

                /*
                 * If intercepting in PREROUTING, we bypass ip_forward().
                 * We must decrement TTL manually and inject into the output path 
                 * to get proper MAC address construction and avoid the destination
                 * dropping our packet or keeping the ingress MAC header.
                 */
                if (state->hook == NF_INET_PRE_ROUTING) {
                    if (iph->ttl <= 1) {
                        kfree_skb(skb);
                        rcu_read_unlock();
                        return NF_STOLEN;
                    }
                    ip_decrease_ttl(iph);

                    /* Clear inner MAC header state so neigh_output rebuilds it */
                    skb->mac_len = 0;
                    skb_reset_mac_header(skb);

                    pr_info("mwan_kmod: [STEERED-PRE] %pI4 -> %pI4 via %s\n",
                            &iph->saddr, &iph->daddr, rt->dst.dev->name);
                            
                    /* Reinject to the output path directly */
                    NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
                            state->net, state->sk, skb,
                            NULL, skb->dev,
                            dst_output);

                    rcu_read_unlock();
                    return NF_STOLEN;
                }

                pr_info("mwan_kmod: [STEERED-OUT] %pI4 -> %pI4 via %s\n",
                        &iph->saddr, &iph->daddr, rt->dst.dev->name);
            }
        }
    }

out:
    rcu_read_unlock();
    return NF_ACCEPT; 
}

static unsigned int mwan_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return mwan_do_steer(skb, state);
}

/* Updated Hooks (PRI_MANGLE to run early) */
static struct nf_hook_ops mwan_nf_ops[] = {
    {
        .hook     = mwan_hook_func,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_MANGLE, 
    },
    {
        .hook     = mwan_hook_func,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_LAST,
    },
};

int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering FORWARD/LOCAL_OUT hooks (After Firewall)\n");
    return nf_register_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}

void mwan_steer_cleanup(void) {
    nf_unregister_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
    pr_info("mwan_kmod: Unregistered steering\n");
}
