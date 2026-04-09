#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/neighbour.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <net/dst.h>

/* Helper to update TCP checksum after MSS modification */
static inline void mwan_tcp_update_csum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    int tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                                    csum_partial(tcph, tcplen, 0));
}

/* Performs TCP MSS Clamping in POST_ROUTING */
static void mwan_clamp_mss(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u8 *opt;
    int optlen;
    u16 new_mss;
    u16 old_mss;
    int i;
    
    // Target MTU of MACsec interface minus IP/TCP overhead (20 + 20)
    u16 target_mtu = dev->mtu; 
    u16 max_mss = target_mtu - 40;

    if (!skb || skb->protocol != htons(ETH_P_IP)) return;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return;

    // Ensure we have enough data for TCP header
    if (!pskb_may_pull(skb, (iph->ihl * 4) + sizeof(struct tcphdr))) return;
    
    // Note: pskb_may_pull might reallocate skb->head, must reload pointers
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));

    // Only process SYN packets
    if (!tcph->syn) return;

    // Ensure we have enough data for TCP options
    if (!pskb_may_pull(skb, (iph->ihl * 4) + (tcph->doff * 4))) return;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));

    optlen = (tcph->doff * 4) - sizeof(struct tcphdr);
    opt = (u8 *)(tcph + 1);

    for (i = 0; i < optlen; ) {
        if (opt[i] == TCPOPT_EOL) {
            break;
        }
        if (opt[i] == TCPOPT_NOP) {
            i++;
            continue;
        }

        if (i + 1 >= optlen || i + opt[i + 1] > optlen) {
            break; // Corrupted options
        }

        if (opt[i] == TCPOPT_MSS && opt[i + 1] == TCPOLEN_MSS) {
            old_mss = (opt[i + 2] << 8) | opt[i + 3];
            
            if (old_mss > max_mss) {
                new_mss = max_mss;
                
                // We are about to modify the packet, ensure it's writable
                if (skb_ensure_writable(skb, (iph->ihl * 4) + (tcph->doff * 4))) {
                    return; // Failed to make writable
                }
                
                // Reload pointers post skb_ensure_writable
                iph = ip_hdr(skb);
                tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));
                opt = (u8 *)(tcph + 1);
                
                opt[i + 2] = (new_mss >> 8) & 0xFF;
                opt[i + 3] = new_mss & 0xFF;
                
                // Always update the TCP checksum after altering payload!
                mwan_tcp_update_csum(skb, iph, tcph);
            }
            break; // found MSS
        }
        i += opt[i + 1]; // move to next option
    }
}

unsigned int mwan_handle_encap_macsec(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;

    if (unlikely(!target_dev)) {
        return NF_ACCEPT;
    }

    /* 1. Perform TCP MSS Clamping to fit within MACsec MTU */
    mwan_clamp_mss(skb, target_dev);

    /* 2. Optional: Check MTU and send ICMP Frag Needed if too large (TODO later for UDP) */
    
    /* 3. Handle MAC Resolution and Injection (Same as encap_none) */
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

    skb->dev = target_dev;
    dev_queue_xmit(skb);

    return NF_STOLEN;
}
