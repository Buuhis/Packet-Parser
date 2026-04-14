#include "mwan_steer.h"
#include "mwan_state.h"
#include "mwan_proto.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/neighbour.h>
#include <net/arp.h>

static bool is_mwan_tunnel(struct mwan_config *cfg, u32 ifindex)
{
    int i;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex)
            return true;
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
    
    /* 3. Steer: Choose a tunnel based on the weight-proportional LUT (O(1)) */
    if (cfg->total_weight > 0 && cfg->num_tunnels > 0) {
        u8 tun_idx = cfg->tunnel_idx_lut[hash & (MWAN_LUT_SIZE - 1)];
        struct mwan_tunnel *tun = &cfg->tunnels[tun_idx];
        
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

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);

    if (!cfg || !cfg->local_dev) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Check if packet is coming from one of our WAN tunnels */
    if (is_mwan_tunnel(cfg, skb->dev->ifindex)) {
        
        /* 1.5. Decrypt if encryption is enabled */
        if (cfg->encrypt_on && cfg->tfm) {
            int iph_len_pre;
            int total_len_pre;
            struct mwan_crypto_hdr *chdr;
            u8 *payload_after_chdr;
            int ciphertext_len;
            u8 iv_buf[MWAN_GCM_IV_LEN];
            struct aead_request *req;
            struct scatterlist sg_rx[MAX_SKB_FRAGS + 2];
            int err_dec, nents;

            /* Ensure we can read enough for IP + Crypto Header */
            iph = ip_hdr(skb);
            iph_len_pre = iph->ihl * 4;
            total_len_pre = ntohs(iph->tot_len);

            if (total_len_pre < iph_len_pre + MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN) {
                /* Packet too small to be encrypted, pass through */
                goto skip_decrypt;
            }

            if (!pskb_may_pull(skb, iph_len_pre + MWAN_CRYPTO_HDR_LEN)) {
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            /* Ensure header is accessible and writable for IP header shift */
            if (skb_header_cloned(skb) || skb_is_nonlinear(skb)) {
                if (unlikely(skb_checksum_help(skb))) {
                    rcu_read_unlock();
                    return NF_ACCEPT;
                }
            }

            if (unlikely(skb_ensure_writable(skb, iph_len_pre + MWAN_CRYPTO_HDR_LEN))) {
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            /* Reload pointers after linearize/writable */
            iph = ip_hdr(skb);
            chdr = (struct mwan_crypto_hdr *)((u8 *)iph + iph_len_pre);

            /* Check magic */
            if (ntohs(chdr->magic) != MWAN_CRYPTO_MAGIC) {
                /* Not an encrypted MWAN packet, pass through */
                goto skip_decrypt;
            }

            /* Build IV from salt + sequence from header */
            memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
            memcpy(iv_buf + MWAN_SALT_LEN, &chdr->seq, 8);

            /* Calculate ciphertext length (includes tag) */
            ciphertext_len = total_len_pre - iph_len_pre - MWAN_CRYPTO_HDR_LEN;
            if (ciphertext_len < MWAN_GCM_TAG_LEN) {
                pr_warn_ratelimited("mwan_kmod: RX decrypt: invalid ciphertext length\n");
                rcu_read_unlock();
                return NF_DROP;
            }

            payload_after_chdr = (u8 *)iph + iph_len_pre + MWAN_CRYPTO_HDR_LEN;

            /* Optimization Point 4: Zero-copy scatterlist for decryption */
            /* Optimization Point 2: Use Pre-allocated Per-CPU Request Pool. */
            if (likely(cfg->crypto_reqs)) {
                req = *this_cpu_ptr(cfg->crypto_reqs);
            } else {
                req = NULL;
            }
            
            if (unlikely(!req)) {
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            sg_init_table(sg_rx, ARRAY_SIZE(sg_rx));
            nents = skb_to_sgvec(skb, sg_rx, iph_len_pre, MWAN_CRYPTO_HDR_LEN + ciphertext_len);
            if (unlikely(nents < 0)) {
                aead_request_free(req);
                rcu_read_unlock();
                return NF_ACCEPT;
            }

            aead_request_set_crypt(req, sg_rx, sg_rx, ciphertext_len, iv_buf);
            aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

            err_dec = crypto_aead_decrypt(req);
            
            if (unlikely(err_dec == -EINPROGRESS || err_dec == -EBUSY)) {
                pr_warn_ratelimited("mwan_kmod: Async crypto in RX - dropping to avoid UAF\n");
                rcu_read_unlock();
                return NF_DROP;
            }

            if (err_dec) {
                pr_warn_ratelimited("mwan_kmod: RX decrypt FAILED (auth tag mismatch, err=%d) — DROP\n", err_dec);
                rcu_read_unlock();
                return NF_DROP;
            }

            /* Decryption success!
             * Optimization Point 1: Zero-copy header removal.
             * Instead of moving payload UP, we move IP Header DOWN by 10 bytes. */
            {
                int plaintext_len = ciphertext_len - MWAN_GCM_TAG_LEN;

                /* Move IP header 10 bytes forward to cover crypto header */
                memmove((u8 *)iph + MWAN_CRYPTO_HDR_LEN, iph, iph_len_pre);
                skb_pull(skb, MWAN_CRYPTO_HDR_LEN);
                skb_reset_network_header(skb);
                
                iph = ip_hdr(skb);
                iph->tot_len = htons(iph_len_pre + plaintext_len);
                iph->check = 0;
                iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

                /* Remove tag from tail */
                skb_trim(skb, iph_len_pre + plaintext_len);

                /* Correct metadata for stack */
                skb_set_transport_header(skb, iph_len_pre);
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }

            /* Reload iph after modifications */
            iph = ip_hdr(skb);
        }

skip_decrypt:
        /* 2. Check if Destination IP matches our Local CIDR */
        if ((iph->daddr & cfg->local_mask) == (cfg->local_ip & cfg->local_mask)) {
            /* 3. Steering: Route to Local Interface */
            
            /* We let the kernel handle the L2 (ARP/MAC) for the client 
             * because the user preferred the kernel to handle it. */
            /* Debug log: Capture info BEFORE switching device */
            if (skb->dev) {
                struct iphdr *iph_dbg = ip_hdr(skb);
                u16 frag_off = ntohs(iph_dbg->frag_off);
                bool is_frag = (frag_off & IP_MF) || (frag_off & IP_OFFSET);

                // pr_info_ratelimited("mwan_kmod: INBOUND [CPU %u] from %s (RXQ: %u) Proto: %u Frag: %s -> To %s\n",
                //                     smp_processor_id(),
                //                     skb->dev->name, 
                //                     skb_rx_queue_recorded(skb) ? skb_get_rx_queue(skb) : 0,
                //                     iph_dbg->protocol,
                //                     is_frag ? "YES" : "NO",
                //                     cfg->local_dev->name);
            }

            skb->dev = cfg->local_dev;
            
            /* Important: Clear any stale L2 header remains to avoid corruption */
            skb_pull(skb, skb_network_offset(skb));
            skb_reset_mac_header(skb);

            /* We return NF_ACCEPT to let the kernel finish routing/delivery locally 
             * to the destination client, now that we've set the correct skb->dev. */
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
