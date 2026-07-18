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
// static inline void mwan_tcp_update_csum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
// {
//     int tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);
//     tcph->check = 0;
//     tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
//                                     csum_partial(tcph, tcplen, 0));
// }

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

    pr_info_ratelimited("mwan_kmod: [MSS Clamp] TCP SYN packet detected. dev MTU: %d, max_mss: %d\n", target_mtu, max_mss);

    // Ensure we have enough data for TCP options
    if (!pskb_may_pull(skb, (iph->ihl * 4) + (tcph->doff * 4))) {
        pr_info_ratelimited("mwan_kmod: [MSS Clamp] pskb_may_pull failed to load TCP options\n");
        return;
    }
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
            pr_info_ratelimited("mwan_kmod: [MSS Clamp] Found MSS option: %d\n", old_mss);
            
            if (old_mss > max_mss) {
                new_mss = max_mss;
                
                // We are about to modify the packet, ensure it's writable
                if (skb_ensure_writable(skb, (iph->ihl * 4) + (tcph->doff * 4))) {
                    pr_info_ratelimited("mwan_kmod: [MSS Clamp] skb_ensure_writable failed\n");
                    return; // Failed to make writable
                }
                
                // Reload pointers post skb_ensure_writable
                iph = ip_hdr(skb);
                tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));
                opt = (u8 *)(tcph + 1);
                
                opt[i + 2] = (new_mss >> 8) & 0xFF;
                opt[i + 3] = new_mss & 0xFF;
                
                pr_info_ratelimited("mwan_kmod: [MSS Clamp] Updated MSS option from %d to %d\n", old_mss, new_mss);
           
                // Always update the TCP checksum after altering payload!
                // mwan_tcp_update_csum(skb, iph, tcph);
                inet_proto_csum_replace2(&tcph->check, skb, htons(old_mss), htons(new_mss), false);

            }
            break; // found MSS
        }
        i += opt[i + 1]; // move to next option
    }
}

unsigned int mwan_handle_encap_macsec(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;
    bool resolved;

    if (unlikely(!target_dev)) {
        pr_info_ratelimited("mwan_kmod: macsec encap failed - target_dev is NULL\n");
        return NF_ACCEPT;
    }

    pr_info_ratelimited("mwan_kmod: macsec encap started for dev %s (ifindex %d, MTU %d), ip_summed %d\n",
                        target_dev->name, target_dev->ifindex, target_dev->mtu, skb->ip_summed);

    /* 1. Perform TCP MSS Clamping to fit within MACsec MTU */
    mwan_clamp_mss(skb, target_dev);

    /* Checksum Fix: Force software checksum calculation before MACsec encapsulation, but skip for GSO packets. Only applies to TCP/UDP. */
    struct iphdr *iph = ip_hdr(skb);
    if (iph && (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
        if (!skb_is_gso(skb) && (skb->ip_summed == CHECKSUM_PARTIAL || skb->ip_summed == CHECKSUM_UNNECESSARY)) {
            pr_info_ratelimited("mwan_kmod: [Checksum Help] Resolving ip_summed %d in software\n", skb->ip_summed);
            if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
                if (iph->protocol == IPPROTO_TCP) {
                    skb->csum_start = ((u8 *)iph + (iph->ihl * 4)) - skb->head;
                    skb->csum_offset = offsetof(struct tcphdr, check);
                    skb->ip_summed = CHECKSUM_PARTIAL;
                } else if (iph->protocol == IPPROTO_UDP) {
                    skb->csum_start = ((u8 *)iph + (iph->ihl * 4)) - skb->head;
                    skb->csum_offset = offsetof(struct udphdr, check);
                    skb->ip_summed = CHECKSUM_PARTIAL;
                }
            }
            if (skb->ip_summed == CHECKSUM_PARTIAL) {
                if (skb_checksum_help(skb)) {
                    pr_info_ratelimited("mwan_kmod: macsec skb_checksum_help failed\n");
                    return NF_ACCEPT;
                }
                pr_info_ratelimited("mwan_kmod: [Checksum Help] skb_checksum_help success, ip_summed is now %d\n", skb->ip_summed);
            }
        }
    }

    /* 2. Optional: Check MTU and send ICMP Frag Needed if too large (TODO later for UDP) */
    
    /* 3. Handle MAC Resolution and Injection (Same as encap_none) */
    if (tun->is_ethernet) {
        resolved = mwan_resolve_gateway_mac(tun, target_dev, tun->gateway_mac);
        pr_info_ratelimited("mwan_kmod: macsec gateway resolution: %s (IP: %pI4, MAC: %pM)\n",
                            resolved ? "RESOLVED" : "PENDING", &tun->gateway, tun->gateway_mac);
        
        if (unlikely(!resolved)) {
            return NF_DROP;
        }

        if (unlikely(skb_headroom(skb) < ETH_HLEN || skb_header_cloned(skb))) {
            if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev))) {
                pr_info_ratelimited("mwan_kmod: macsec skb_cow_head failed\n");
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
        pr_info_ratelimited("mwan_kmod: macsec target dev %s is not ethernet\n", target_dev->name);
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

    {
        int ret;
        skb->dev = target_dev;
        ret = dev_queue_xmit(skb);
        pr_info_ratelimited("mwan_kmod: macsec redirecting packet to %s, dev_queue_xmit returned %d\n", target_dev->name, ret);
        return NF_STOLEN;
    }
}
