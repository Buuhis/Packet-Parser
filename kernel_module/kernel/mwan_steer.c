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

/**
 * mwan_get_neigh_mac - Get MAC address for a gateway IP from ARP cache
 * @dev: The egress device
 * @gw_ip: Gateway IP in network byte order
 * @mac: Buffer to store the 6-byte MAC address
 * 
 * Returns 0 if MAC found and valid, -1 otherwise.
 */
static int mwan_get_neigh_mac(struct net_device *dev, __be32 gw_ip, unsigned char *mac)
{
    struct neighbour *n;
    int ret = -1;

    /* Search for the neighbor in the ARP table (ipv4_neigh_lookup) */
    n = neigh_lookup(&arp_tbl, &gw_ip, dev);
    if (n) {
        if (n->nud_state & NUD_VALID) {
            read_lock_bh(&n->lock);
            memcpy(mac, n->ha, ETH_ALEN);
            read_unlock_bh(&n->lock);
            ret = 0;
        } else {
            /* Trigger ARP request if not valid yet */
            neigh_event_send(n, NULL);
        }
        neigh_release(n);
    } else {
        /* Create a new neighbor entry if it doesn't exist to trigger ARP */
        n = neigh_create(&arp_tbl, &gw_ip, dev);
        if (!IS_ERR(n)) {
            neigh_event_send(n, NULL);
            neigh_release(n);
        }
    }
    return ret;
}

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

        /* 4. Magic: Re-routing and Dynamic MAC Resolution */
        if (target_ifindex != 0) {
            unsigned char resolved_mac[ETH_ALEN];
            
            target_dev = dev_get_by_index(state->net, target_ifindex);
            if (!target_dev) {
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            /* Resolve Gateway MAC from ARP Cache */
            if (mwan_get_neigh_mac(target_dev, gateway ? gateway : iph->daddr, resolved_mac) != 0) {
                /* MAC not resolved yet. Fallback to Slow-path to trigger ARP naturally */
                pr_info_ratelimited("mwan_kmod: ARP miss for %pI4 on %s. Using slow-path.\n",
                                    &gateway, target_dev->name);
                dev_put(target_dev);
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            /* Fast-path: We have the MAC, so we manually build Header and XMIT */
            if (skb_headroom(skb) < ETH_HLEN) {
                struct sk_buff *new_skb = skb_realloc_headroom(skb, ETH_HLEN);
                if (!new_skb) {
                    dev_put(target_dev);
                    rcu_read_unlock();
                    return NF_ACCEPT; 
                }
                consume_skb(skb);
                skb = new_skb;
                /* Re-point pointers after realloc */
                iph = ip_hdr(skb);
            }

            /* Build Ethernet Header */
            skb_push(skb, ETH_HLEN);
            skb_reset_mac_header(skb);
            {
                struct ethhdr *eth = eth_hdr(skb);
                
                if (target_dev->dev_addr) {
                    memcpy(eth->h_source, target_dev->dev_addr, ETH_ALEN);
                } else {
                    eth_zero_addr(eth->h_source);
                }
                
                memcpy(eth->h_dest, resolved_mac, ETH_ALEN);
                eth->h_proto = htons(ETH_P_IP);

                /* Final Egress Log */
                pr_info("mwan_kmod: [FAST-OUT] %pI4 -> %pI4 via %s | DST_MAC: %pM\n",
                        &iph->saddr, &iph->daddr, target_dev->name, eth->h_dest);
            }

            skb->dev = target_dev;
            dev_queue_xmit(skb);

            dev_put(target_dev);
            rcu_read_unlock();
            return NF_STOLEN;
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