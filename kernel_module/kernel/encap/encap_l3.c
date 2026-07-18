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
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <net/gso.h>
#else
#include <linux/skbuff.h>
#endif

/* Helper to update TCP checksum after MSS modification */
static inline void mwan_tcp_update_csum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    int tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                                    csum_partial(tcph, tcplen, 0));
}

/* Performs TCP MSS Clamping to account for 26-byte encryption overhead.
 * This ensures packets don't exceed MTU after encryption. */
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

static unsigned int mwan_handle_encap_l3_single(struct sk_buff *skb, struct mwan_tunnel *tun);

unsigned int mwan_handle_encap_l3(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    if (skb_is_gso(skb)) {
        struct sk_buff *segs, *nskb, *next;
        netdev_features_t features = netif_skb_features(skb);

        /* Force software segmentation by clearing all GSO features */
        segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
        if (IS_ERR(segs) || !segs) {
            return NF_DROP;
        }

        nskb = segs;
        while (nskb) {
            next = nskb->next;
            nskb->next = NULL;

            /* Each segment must be processed and transmitted. 
             * If processing fails, we must free it to avoid memory leaks. */
            if (mwan_handle_encap_l3_single(nskb, tun) != NF_STOLEN) {
                kfree_skb(nskb);
            }

            nskb = next;
        }
        consume_skb(skb);
        return NF_STOLEN;
    }

    return mwan_handle_encap_l3_single(skb, tun);
}

static unsigned int mwan_handle_encap_l3_single(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;
    struct mwan_config *cfg;
    struct iphdr *iph;
    struct crypto_aead *tfm;
    struct aead_request *req = NULL;
    struct scatterlist sg[2];     /* AAD (CryptoHdr) | Ciphertext+Tag */
    u8 iv[MWAN_GCM_IV_LEN];
    struct mwan_crypto_hdr *chdr;
    u64 seq;
    int payload_len;
    int iph_len;
    int err;

    if (unlikely(!target_dev)) return NF_ACCEPT;

    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->encrypt_on || !cfg->tfm)
        return mwan_handle_encap_none(skb, tun);

    /* MTU Protection: Clamp TCP MSS before encryption */
    mwan_clamp_mss(skb, target_dev);

    tfm = cfg->tfm;
    iph = ip_hdr(skb);
    iph_len = iph->ihl * 4;
    payload_len = ntohs(iph->tot_len) - iph_len;
    if (payload_len <= 0) return mwan_handle_encap_none(skb, tun);

    /* Entropy Fix: Calculate the flow hash of the plaintext packet BEFORE encryption.
     * This hash is essential for the tunnel driver (e.g. VXLAN) to generate 
     * varied source ports, which in turn allows RSS on the receiver side 
     * to distribute traffic across multiple CPU cores. */
    skb_get_hash(skb);

    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    memcpy(iv, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv + MWAN_SALT_LEN) = cpu_to_be64(seq);

    if (skb_linearize(skb)) return NF_ACCEPT;
    if (skb_cow(skb, LL_RESERVED_SPACE(target_dev) + MWAN_CRYPTO_HDR_LEN)) return NF_ACCEPT;
    if (pskb_expand_head(skb, 0, MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN, GFP_ATOMIC)) return NF_ACCEPT;

    /* Checksum Fix (Step 1): Resolve partial checksums before we encrypt the payload.
     * If we don't do this, the ciphertext will contain an invalid (likely 0) checksum,
     * or worse, the NIC will try to calculate it later and corrupt the ciphertext. */
    if (skb->ip_summed == CHECKSUM_PARTIAL || skb->ip_summed == CHECKSUM_UNNECESSARY) {
        if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
            struct iphdr *iph = ip_hdr(skb);
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
                return NF_ACCEPT;
            }
        }
    }

    iph = ip_hdr(skb);
    {
        u8 *payload_start = (u8 *)iph + iph_len;
        skb_put(skb, MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN);
        memmove(payload_start + MWAN_CRYPTO_HDR_LEN, payload_start, payload_len);
        chdr = (struct mwan_crypto_hdr *)payload_start;
        chdr->magic = htons(MWAN_CRYPTO_MAGIC);
        chdr->proto = iph->protocol;
        chdr->reserved = 0;
        chdr->seq = cpu_to_be64(seq);
    }

    /* Finalize IP Header before encryption AAD (though we use CryptoHdr as AAD now) */
    iph = ip_hdr(skb);
    iph->protocol = MWAN_FAKE_PROTOCOL;
    iph->tot_len = htons(iph_len + MWAN_CRYPTO_HDR_LEN + payload_len + MWAN_GCM_TAG_LEN);
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) return NF_ACCEPT;

    {
        u8 *aad_ptr = (u8 *)chdr;                                 /* AAD = Crypto Header (Immutable) */
        u8 *pt_ptr  = (u8 *)chdr + MWAN_CRYPTO_HDR_LEN;           /* Plaintext follows AAD */
        
        /* SG list: [AAD (10B)] [Plaintext/Ciphertext (payload_len)] [Tag space (16B)] 
         * Note: We use 2 SG entries here for clarity: AAD and following data. */
        sg_init_table(sg, 2);
        sg_set_buf(&sg[0], aad_ptr, MWAN_CRYPTO_HDR_LEN);         /* AAD: Crypto Hdr */
        sg_set_buf(&sg[1], pt_ptr, payload_len + MWAN_GCM_TAG_LEN); /* Plaintext/Tag space */

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
    }
    aead_request_free(req);

    /* Checksum Fix (Step 2): Inform the kernel/NIC that the payload is now ciphertext
     * and no longer needs (or can have) L4 checksum calculation. This prevents
     * hardware offloads from overwriting bytes in our encrypted data. */
    skb->ip_summed = CHECKSUM_NONE;

    /* Handle L2 injection */
    if (tun->is_ethernet) {
        if (unlikely(!mwan_resolve_gateway_mac(tun, target_dev, tun->gateway_mac))) {
            return NF_DROP;
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
        skb_set_queue_mapping(skb, smp_processor_id() % target_dev->real_num_tx_queues);
    }

    iph = ip_hdr(skb);
    if (iph) {
        skb_set_transport_header(skb, iph->ihl * 4);
    }

    // pr_info("mwan_kmod: AFTER (L3) - Redirecting to: %s\n", target_dev->name);
    skb->dev = target_dev;
    dev_queue_xmit(skb);
    return NF_STOLEN;
}
