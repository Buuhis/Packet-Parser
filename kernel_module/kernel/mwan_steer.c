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
     * (Simplified here: just IP and protocol)
     */
    hash = jhash_3words((__force u32)iph->saddr, (__force u32)iph->daddr, iph->protocol, 0x12345678);
    
    /* 3. Steer: Choose a pre-existing tunnel based on the hash */
    {
        /* TODO: Real implementation should factor in weights. This is Round Robin / Hash Modulo. */
        u32 idx = hash % cfg->num_tunnels;
        target_ifindex = cfg->tunnels[idx].ifindex;
    }
    rcu_read_unlock();

    /* No valid interface index found */
    if (target_ifindex == 0) return NF_ACCEPT;

    /* Get the target net_device */
    target_dev = dev_get_by_index(dev_net(skb->dev), target_ifindex);
    if (!target_dev) return NF_ACCEPT;

    /* If it's already going out this device, we don't need to do anything */
    if (skb->dev == target_dev) {
        dev_put(target_dev);
        return NF_ACCEPT; 
    }

    /* 4. Magic: Change the Egress Device
     * At this point, the firewall has allowed it. We assign the un-fragmented packet to the VXLAN device.
     * The Linux network stack's downstream `dev_queue_xmit` will perform MTU checks
     * and automatically fragment it (RFC 791) if it exceeds the VXLAN's 1418 MTU.
     */
    skb->dev = target_dev;
    skb_clear_hash(skb);
    
    /* Log for debugging */
    pr_debug("mwan_kmod: Steering flow %pI4 -> %pI4 through %s\n", 
             &iph->saddr, &iph->daddr, target_dev->name);
           
    dev_put(target_dev);
    
    /* 5. Return ACCEPT
     * Why ACCEPT and not STOLEN? Because we merely altered the skb->dev property. 
     * The Linux IP Output pipeline (ip_finish_output) will read this modified `skb->dev` 
     * and push it out the new interface natively.
     */
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
