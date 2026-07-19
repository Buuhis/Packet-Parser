#include "mwan_steer.h"
#include "mwan_state.h"
#include "mwan_proto.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>

#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <linux/inetdevice.h>

bool mwan_resolve_gateway_mac(struct mwan_tunnel *tun, struct net_device *dev, u8 *mac_out)
{
    struct neighbour *n;
    bool resolved = false;
    struct in_device *in_dev;

    /* Enforce rp_filter = 0 dynamically */
    rcu_read_lock();
    in_dev = __in_dev_get_rcu(dev);
    if (in_dev && in_dev->cnf.data[IPV4_DEVCONF_RP_FILTER - 1] != 0) {
        in_dev->cnf.data[IPV4_DEVCONF_RP_FILTER - 1] = 0;
    }
    rcu_read_unlock();

    /* Look up gateway MAC locklessly in kernel's neighbour table */
    n = __ipv4_neigh_lookup_noref(dev, tun->gateway);
    if (n) {
        if (n->nud_state & NUD_VALID) {
            read_lock_bh(&n->lock);
            ether_addr_copy(mac_out, n->ha);
            read_unlock_bh(&n->lock);
            resolved = true;
        } else {
            neigh_event_send(n, NULL);
        }
    } else {
        n = neigh_create(&arp_tbl, &tun->gateway, dev);
        if (n && !IS_ERR(n)) {
            neigh_event_send(n, NULL);
            neigh_release(n);
        }
    }

    /* Fallback: If neighbour state is pending/invalid but we already have a cached non-zero MAC, use it! */
    if (!resolved && !is_zero_ether_addr(tun->gateway_mac)) {
        ether_addr_copy(mac_out, tun->gateway_mac);
        resolved = true;
    }

    return resolved;
}

static bool is_mwan_tunnel(struct mwan_config *cfg, u32 ifindex)
{
    int i;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex)
            return true;
    }
    return false;
}

/* Helper function to check if packet is PQC handshake traffic (UDP port 7090) */
static inline bool is_pqc_handshake_packet(struct sk_buff *skb, struct iphdr *iph)
{
    if (iph && iph->protocol == IPPROTO_UDP) {
        int ip_hlen = iph->ihl * 4;
        struct udphdr *udph;
        
        // Ensure we can access the UDP header safely
        if (!pskb_may_pull(skb, ip_hlen + sizeof(struct udphdr)))
            return false;
        
        // Reload iph/udph after pskb_may_pull as skb header pointers may change
        iph = ip_hdr(skb);
        udph = (struct udphdr *)(skb_network_header(skb) + ip_hlen);
        
        if (udph->dest == htons(7090) || udph->source == htons(7090)) {
            return true;
        }
    }
    return false;
}

/* The core TX steering logic */
static unsigned int mwan_hook_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    
    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // pr_info_ratelimited("mwan_kmod: POST_ROUTING hit: dest %pI4, out_dev: %s (ifindex: %d)\n",
    //                     &iph->daddr, state->out ? state->out->name : "NULL",
    //                     state->out ? state->out->ifindex : -1);

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    
    if (!cfg || cfg->num_tunnels == 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Filter: Check if Outbound Interface is managed by MWAN */
    if (!state->out || !is_mwan_tunnel(cfg, state->out->ifindex)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Bypass PQC handshake traffic (UDP port 7090) */
    if (is_pqc_handshake_packet(skb, iph)) {
        int i;
        struct mwan_tunnel *tun = NULL;
        for (i = 0; i < cfg->num_tunnels; i++) {
            if (cfg->tunnels[i].ifindex == state->out->ifindex) {
                tun = &cfg->tunnels[i];
                break;
            }
        }
        if (tun) {
            unsigned int ret = mwan_handle_encap_none(skb, tun);
            rcu_read_unlock();
            return ret;
        }
    }

    pr_info_ratelimited("mwan_kmod: MATCHED managed tunnel: %s (ifindex: %d). Steering flow...\n",
                        state->out->name, state->out->ifindex);

    /* MTU Protection: Let kernel IP stack fragment non-GSO packets that exceed the tunnel MTU */
    if (!skb_is_gso(skb) && skb->len > state->out->mtu) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 2. Hash: Use kernel-cached/hardware RSS hash, but fallback to custom L3-only hash for IP fragments */
    if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
        hash = (__force u32)iph->saddr ^ (__force u32)iph->daddr;
    } else {
        hash = skb_get_hash(skb);
    }
    
    /* 3. Steer: Choose a tunnel based on the weight-proportional LUT (O(1)) */
    if (cfg->total_weight > 0 && cfg->num_tunnels > 0) {
        u8 tun_idx = cfg->tunnel_idx_lut[hash & (MWAN_LUT_SIZE - 1)];
        struct mwan_tunnel *tun = &cfg->tunnels[tun_idx];
        
        // pr_info_ratelimited("mwan_kmod: steer packet to %pI4 - hash: 0x%x, lut_idx: %d, tunnel: %s, mac_resolved: %d, dev_ptr: %px\n",
        //                     &iph->daddr, hash, hash & (MWAN_LUT_SIZE - 1), 
        //                     tun->dev ? tun->dev->name : "NULL", tun->mac_resolved, tun->dev);

        unsigned int ret = NF_ACCEPT;
        
        switch (tun->encap_type) {
            case MWAN_ENCAP_NONE:
                ret = mwan_handle_encap_none(skb, tun);
                break;
            case MWAN_ENCAP_MACSEC:
                ret = mwan_handle_encap_macsec(skb, tun);
                break;
            case MWAN_ENCAP_L3_CUSTOM:
                ret = mwan_handle_encap_l3(skb, tun);
                break;
            default:
                ret = mwan_handle_encap_none(skb, tun);
                break;
        }
        
        rcu_read_unlock();
        return ret;
    }


    rcu_read_unlock();
    return NF_ACCEPT; 
}

/* The core Inbound processing logic */
static unsigned int mwan_hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;

    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // if (skb->dev && (strncmp(skb->dev->name, "ne_", 3) == 0 ||
    //                  strncmp(skb->dev->name, "l2tun", 5) == 0 ||
    //                  strncmp(skb->dev->name, "enp", 3) == 0 ||
    //                  strncmp(skb->dev->name, "eno", 3) == 0)) {
    //     static int rx_debug_count = 0;
    //     if (rx_debug_count < 100) {
    //         rx_debug_count++;
    //         pr_info("mwan_kmod: [RX debug %d] dev %s, proto %d, len %d, saddr %pI4, daddr %pI4\n",
    //                 rx_debug_count, skb->dev->name, iph->protocol, skb->len, &iph->saddr, &iph->daddr);
    //     }
    // }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);

    if (!cfg) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Check if packet is coming from one of our WAN tunnels */
    if (is_mwan_tunnel(cfg, skb->dev->ifindex)) {
        /* Bypass decryption for PQC handshake packets */
        if (is_pqc_handshake_packet(skb, iph)) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }
        pr_info_ratelimited("mwan_kmod: PRE_ROUTING hit from tunnel %s, proto %d, saddr %pI4, daddr %pI4\n",
                            skb->dev->name, iph->protocol, &iph->saddr, &iph->daddr);
        
        /* 2. Decrypt if encryption is enabled (L3 custom mode) */
        if (cfg->encrypt_on && cfg->tfm) {
            int dec_ret = mwan_handle_decap_l3(skb, cfg);
            if (dec_ret != MWAN_DECAP_CONTINUE) {
                pr_info_ratelimited("mwan_kmod: PRE_ROUTING decryption failed/drop with ret %d\n", dec_ret);
                rcu_read_unlock();
                return (unsigned int)dec_ret;
            }
        }
    }

    rcu_read_unlock();
    return NF_ACCEPT;
}

/* Netfilter Hook Definitions */
static struct nf_hook_ops mwan_nf_ops[] = {
    {
        .hook     = mwan_hook_post_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_LAST, 
    },
    {
        .hook     = mwan_hook_pre_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST, 
    },
};

/* Hook Registration */
int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering Netfilter steering hooks\n");
    return nf_register_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hooks\n");
    nf_unregister_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}
