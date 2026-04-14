#include "../mwan_steer.h"
#include "../mwan_proto.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
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

/* Performs TCP MSS Clamping to account for 26-byte encryption overhead. */
static void mwan_clamp_mss(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u8 *opt;
    int optlen;
    u16 new_mss, old_mss;
    u16 max_mss = dev->mtu - 40 - (MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN); 
    int i;

    if (!skb || skb->protocol != htons(ETH_P_IP)) return;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return;

    if (!pskb_may_pull(skb, (iph->ihl * 4) + sizeof(struct tcphdr))) return;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));
    if (!tcph->syn) return;

    if (!pskb_may_pull(skb, (iph->ihl * 4) + (tcph->doff * 4))) return;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));

    optlen = (tcph->doff * 4) - sizeof(struct tcphdr);
    opt = (u8 *)(tcph + 1);

    for (i = 0; i < optlen; ) {
        if (opt[i] == TCPOPT_EOL) break;
        if (opt[i] == TCPOPT_NOP) { i++; continue; }
        if (i + 1 >= optlen || i + opt[i + 1] > optlen) break;

        if (opt[i] == TCPOPT_MSS && opt[i + 1] == TCPOLEN_MSS) {
            old_mss = (opt[i + 2] << 8) | opt[i + 3];
            if (old_mss > max_mss) {
                new_mss = max_mss;
                if (skb_ensure_writable(skb, (iph->ihl * 4) + (tcph->doff * 4))) return;
                iph = ip_hdr(skb);
                tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));
                opt = (u8 *)(tcph + 1);
                opt[i + 2] = (new_mss >> 8) & 0xFF;
                opt[i + 3] = new_mss & 0xFF;
                mwan_tcp_update_csum(skb, iph, tcph);
            }
            break;
        }
        i += opt[i + 1];
    }
}

unsigned int mwan_handle_encap_l3(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;
    struct mwan_config *cfg;
    struct iphdr *iph;
    struct crypto_aead *tfm;
    struct aead_request *req = NULL;
    struct scatterlist sg[MAX_SKB_FRAGS + 2];
    u8 iv[MWAN_GCM_IV_LEN];
    struct mwan_crypto_hdr *chdr;
    u64 seq;
    int payload_len, iph_len;
    int err, nents;

    if (unlikely(!target_dev)) return NF_ACCEPT;

    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->encrypt_on || !cfg->tfm)
        return mwan_handle_encap_none(skb, tun);

    mwan_clamp_mss(skb, target_dev);

    tfm = cfg->tfm;
    iph = ip_hdr(skb);
    iph_len = iph->ihl * 4;
    payload_len = ntohs(iph->tot_len) - iph_len;

    if (payload_len <= 0) return mwan_handle_encap_none(skb, tun);

    /* Checksum Fix: Resolve partical cs before headers are moved/encrypted */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (unlikely(skb_checksum_help(skb))) return NF_ACCEPT;
        iph = ip_hdr(skb);
    }

    /* Optimization Point 4 & 1: Zero-Copy Preparation.
     * We need 10B headroom to move IP header back, and 16B tailroom for Tag.
     * skb_cow_data handles fragmented skbs much better than skb_linearize. */
    if (unlikely(skb_cow_head(skb, 10))) return NF_ACCEPT;
    {
        struct sk_buff *trailer;
        if (unlikely(skb_cow_data(skb, MWAN_GCM_TAG_LEN, &trailer) < 0)) return NF_ACCEPT;
    }

    /* Reload pointers after potential reallocations */
    iph = ip_hdr(skb);

    /* Move IP Header 10 bytes back into headroom. 
     * This is much faster than moving the entire payload forward. */
    memmove((u8 *)iph - MWAN_CRYPTO_HDR_LEN, iph, iph_len);
    skb_push(skb, MWAN_CRYPTO_HDR_LEN);
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    
    /* The 10-byte gap between new IP header and payload is where chdr goes */
    chdr = (struct mwan_crypto_hdr *)((u8 *)iph + iph_len);
    
    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    memcpy(iv, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv + MWAN_SALT_LEN) = cpu_to_be64(seq);

    chdr->magic = htons(MWAN_CRYPTO_MAGIC);
    chdr->seq = cpu_to_be64(seq);

    /* Update IP Header size and checksum */
    iph->tot_len = htons(iph_len + MWAN_CRYPTO_HDR_LEN + payload_len + MWAN_GCM_TAG_LEN);
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    /* Extend skb to cover the tag at the end */
    skb_put(skb, MWAN_GCM_TAG_LEN);

    /* Entropy Fix: Calculate hash based on plaintext (now at chdr + 10) */
    skb_get_hash(skb);

    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) return NF_ACCEPT;

    /* OPTIMIZATION POINT 4: Scatterlist on Non-Linear SKB.
     * We build the SG table from the data after the IP header.
     * This avoids expensive skb_linearize()! */
    sg_init_table(sg, ARRAY_SIZE(sg));
    nents = skb_to_sgvec(skb, sg, iph_len, MWAN_CRYPTO_HDR_LEN + payload_len + MWAN_GCM_TAG_LEN);
    if (unlikely(nents < 0)) {
        aead_request_free(req);
        return NF_ACCEPT;
    }

    /* AAD is just the 10B Crypto Header which is at the very beginning of our SG list */
    aead_request_set_crypt(req, sg, sg, payload_len, iv);
    aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

    err = crypto_aead_encrypt(req);
    if (unlikely(err == -EINPROGRESS || err == -EBUSY)) {
        pr_warn_ratelimited("mwan_kmod: Async crypto in TX detected - dropping\n");
        aead_request_free(req);
        return NF_ACCEPT;
    }

    if (err) {
        pr_warn_ratelimited("mwan_kmod: Encrypt failed: %d\n", err);
        aead_request_free(req);
        return NF_ACCEPT;
    }
    aead_request_free(req);

    /* Checksum Fix (Step 2): Inform NIC to skip L4 checksum on ciphertext */
    skb->ip_summed = CHECKSUM_NONE;

    /* Handle L2 injection */
    if (tun->is_ethernet) {
        if (unlikely(!tun->mac_resolved)) {
            struct neighbour *n = neigh_lookup(&arp_tbl, &tun->gateway, target_dev);
            if (!n) n = neigh_create(&arp_tbl, &tun->gateway, target_dev);
            if (n && !IS_ERR(n)) {
                if (n->nud_state & NUD_VALID) {
                    read_lock_bh(&n->lock);
                    ether_addr_copy(tun->gateway_mac, n->ha);
                    read_unlock_bh(&n->lock);
                    tun->mac_resolved = true;
                } else neigh_event_send(n, NULL);
                neigh_release(n);
            }
            if (!tun->mac_resolved) return NF_ACCEPT;
        }

        if (unlikely(skb_headroom(skb) < ETH_HLEN || skb_header_cloned(skb))) {
            if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev))) return NF_ACCEPT;
        }

        skb_push(skb, ETH_HLEN);
        skb_reset_mac_header(skb);
        {
            struct ethhdr *eth = eth_hdr(skb);
            if (target_dev->dev_addr) ether_addr_copy(eth->h_source, target_dev->dev_addr);
            else eth_zero_addr(eth->h_source);
            ether_addr_copy(eth->h_dest, tun->gateway_mac);
            eth->h_proto = htons(ETH_P_IP);
        }
    } else {
        skb_pull(skb, skb_network_offset(skb));
        skb_reset_mac_header(skb);
    }

    if (likely(target_dev->real_num_tx_queues > 1)) {
        skb_set_queue_mapping(skb, skb_get_hash(skb) % target_dev->real_num_tx_queues);
    }

    skb->dev = target_dev;
    dev_queue_xmit(skb);
    return NF_STOLEN;
}
