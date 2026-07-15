#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <net/neighbour.h>
#include <net/arp.h>

unsigned int mwan_handle_encap_none(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;

    if (unlikely(!target_dev)) {
        return NF_ACCEPT;
    }

    if (tun->is_ethernet) {
        if (unlikely(!tun->mac_resolved)) {
            struct neighbour *n = neigh_lookup(&arp_tbl, &tun->gateway, target_dev);
            if (!n) {
                n = neigh_create(&arp_tbl, &tun->gateway, target_dev);
            }
            
            if (n && !IS_ERR(n)) {
                if (n->nud_state & NUD_VALID) {
                    read_lock_bh(&n->lock);
                    ether_addr_copy(tun->gateway_mac, n->ha);
                    read_unlock_bh(&n->lock);
                    tun->mac_resolved = true;
                } else {
                    neigh_event_send(n, NULL);
                }
                neigh_release(n);
            }

            if (!tun->mac_resolved) {
                return NF_ACCEPT;
            }
        }

        if (unlikely(skb_headroom(skb) < ETH_HLEN || skb_header_cloned(skb))) {
            if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev))) {
                return NF_ACCEPT; 
            }
        }

        skb_push(skb, ETH_HLEN);
        skb_reset_mac_header(skb);
        {
            struct ethhdr *eth = eth_hdr(skb);
            if (target_dev->dev_addr)
                ether_addr_copy(eth->h_source, target_dev->dev_addr);
            else
                eth_zero_addr(eth->h_source);
            
            ether_addr_copy(eth->h_dest, tun->gateway_mac);
            eth->h_proto = htons(ETH_P_IP);
        }
    } else {
        skb_pull(skb, skb_network_offset(skb));
        skb_reset_mac_header(skb);
    }

    if (likely(target_dev->real_num_tx_queues > 1)) {
        u16 cpu_id = smp_processor_id();
        u16 q_idx = cpu_id % target_dev->real_num_tx_queues;
        
        skb_set_queue_mapping(skb, q_idx);
    }

    {
        struct iphdr *iph = ip_hdr(skb);
        if (iph) {
            skb_set_transport_header(skb, iph->ihl * 4);
        }
    }

    // pr_info("mwan_kmod: AFTER (NONE) - Redirecting to: %s\n", target_dev->name);
    skb->dev = target_dev;
    dev_queue_xmit(skb);

    return NF_STOLEN;
}
