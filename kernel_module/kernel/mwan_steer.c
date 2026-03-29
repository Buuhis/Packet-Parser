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
                
                if (unlikely(!target_dev)) {
                    break;
                }

                /* 4. Magic: Re-routing and MAC Injection */
                
                /* If it's an Ethernet device, we need a resolved MAC */
                if (tun->is_ethernet) {
                    if (unlikely(!tun->mac_resolved)) {
                        /* Fallback to standard path if MAC is not resolved */
                        break;
                    }

                    /* --- OPTIMIZATION: MTU Check --- */
                    if (unlikely(skb->len + ETH_HLEN > target_dev->mtu)) {
                        /* Packet too large for target MTU, avoid fragmentation slow-path */
                        break;
                    }

                    /* --- OPTIMIZATION: Selective Headroom Expansion --- 
                     * skb_cow_head will only reallocate if headroom < needed OR if the skb is cloned. 
                     * Since we are in Netfilter, clones are common but we must ensure we don't 
                     * unnecessarily reallocate if headroom is already sufficient for our 14-byte header.
                     */
                    if (skb_headroom(skb) < LL_RESERVED_SPACE(target_dev) || skb_header_cloned(skb)) {
                        if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev))) {
                            break;
                        }
                    }

                    /* Prepend Ethernet Header */
                    skb_push(skb, ETH_HLEN);
                    skb_reset_mac_header(skb);
                    {
                        struct ethhdr *eth = eth_hdr(skb);
                        if (target_dev->dev_addr)
                            memcpy(eth->h_source, target_dev->dev_addr, ETH_ALEN);
                        else
                            eth_zero_addr(eth->h_source);
                        
                        memcpy(eth->h_dest, tun->gateway_mac, ETH_ALEN);
                        eth->h_proto = iph->version == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
                    }

                    /* --- OPTIMIZATION: Hardware Checksum Offload --- 
                     * Tell the NIC to handle the IP/UDP checksums if capable. 
                     */
                    if (target_dev->features & (NETIF_F_IP_CSUM | NETIF_F_HW_CSUM)) {
                        skb->ip_summed = CHECKSUM_PARTIAL;
                        skb->csum_start = skb_transport_header(skb) - skb->head;
                        skb->csum_offset = offsetof(struct udphdr, check);
                    }
                } else {
                    /* Non-ethernet device (Point-to-Point tunnel) */
                    skb_pull(skb, skb_network_offset(skb));
                    skb_reset_mac_header(skb);
                }

                /* Final Egress */
                skb->dev = target_dev;
                
                /* Reset transport and network header pointers relative to skb->data */
                skb_set_network_header(skb, (unsigned char *)iph - skb->data);
                
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