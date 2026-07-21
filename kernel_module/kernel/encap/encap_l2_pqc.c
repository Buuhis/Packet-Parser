#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/neighbour.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <net/dst.h>
#include <crypto/aead.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <net/gso.h>
#else
#include <linux/skbuff.h>
#endif

static unsigned int mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun);

unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
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
            if (mwan_handle_encap_l2_pqc_single(nskb, tun) != NF_STOLEN) {
                kfree_skb(nskb);
            }

            nskb = next;
        }
        consume_skb(skb);
        return NF_STOLEN;
    }

    return mwan_handle_encap_l2_pqc_single(skb, tun);
}

static unsigned int mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct mwan_config *cfg;
    struct net_device *target_dev = tun->dev;
    struct crypto_aead *tfm;
    struct aead_request *req;
    u8 iv[MWAN_GCM_IV_LEN];
    struct mwan_crypto_hdr *chdr;
    u64 seq;
    int ip_pkt_len, err;
    bool resolved;

    if (unlikely(!target_dev)) {
        return NF_ACCEPT;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (unlikely(!cfg || !cfg->tfm || !cfg->encrypt_on)) {
        rcu_read_unlock();
        return mwan_handle_encap_none(skb, tun);
    }

    tfm = cfg->tfm;
    ip_pkt_len = skb->len;
    if (ip_pkt_len <= 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb))) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }
    }

    // Dynamic resolution of gateway MAC for L2 tunnel if ethernet
    if (tun->is_ethernet) {
        resolved = mwan_resolve_gateway_mac(tun, target_dev, tun->gateway_mac);
        if (unlikely(!resolved)) {
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    memcpy(iv, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv + MWAN_SALT_LEN) = cpu_to_be64(seq);

    // Expand skb headroom/tailroom for Ethernet header + Crypto header + Tag
    if (skb_cow(skb, LL_RESERVED_SPACE(target_dev) + ETH_HLEN + MWAN_CRYPTO_HDR_LEN)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }
    if (skb_tailroom(skb) < MWAN_GCM_TAG_LEN) {
        if (pskb_expand_head(skb, 0, MWAN_GCM_TAG_LEN, GFP_ATOMIC)) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }
    }

    u8 tmp_src[ETH_ALEN], tmp_dst[ETH_ALEN];
    bool has_mac = false;

    // Check if the skb already has a valid MAC header (bridged packet)
    if (skb_mac_header_was_set(skb) && 
        skb_mac_header(skb) >= skb->head && 
        skb_mac_header(skb) < skb->data) {
        struct ethhdr *orig_eth = eth_hdr(skb);
        ether_addr_copy(tmp_src, orig_eth->h_source);
        ether_addr_copy(tmp_dst, orig_eth->h_dest);
        has_mac = true;
    }

    // Prepend Ethernet + Crypto Header
    skb_push(skb, ETH_HLEN + MWAN_CRYPTO_HDR_LEN);
    skb_reset_mac_header(skb);

    // Write Ethernet Header
    struct ethhdr *eth = eth_hdr(skb);
    if (has_mac) {
        ether_addr_copy(eth->h_source, tmp_src);
        ether_addr_copy(eth->h_dest, tmp_dst);
    } else {
        if (target_dev->dev_addr)
            ether_addr_copy(eth->h_source, target_dev->dev_addr);
        else
            eth_zero_addr(eth->h_source);
        
        if (tun->is_ethernet)
            ether_addr_copy(eth->h_dest, tun->gateway_mac);
        else
            eth_zero_addr(eth->h_dest);
    }
    eth->h_proto = htons(MWAN_L2_PQC_ETHERTYPE);

    // Write Crypto Header
    chdr = (struct mwan_crypto_hdr *)(skb->data + ETH_HLEN);
    chdr->magic = htons(MWAN_CRYPTO_MAGIC);
    // Store original IP packet length in proto and reserved fields (16-bit value)
    chdr->proto = (ip_pkt_len >> 8) & 0xFF;
    chdr->reserved = ip_pkt_len & 0xFF;
    chdr->seq = cpu_to_be64(seq);

    // Put Tag space at the tail
    skb_put(skb, MWAN_GCM_TAG_LEN);

    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], (u8 *)chdr, MWAN_CRYPTO_HDR_LEN); // AAD
        
        nents = skb_to_sgvec(skb, &sg[1], ETH_HLEN + MWAN_CRYPTO_HDR_LEN, ip_pkt_len + MWAN_GCM_TAG_LEN);
        if (unlikely(nents < 0)) {
            aead_request_free(req);
            rcu_read_unlock();
            return NF_ACCEPT;
        }

        aead_request_set_crypt(req, sg, sg, ip_pkt_len, iv);
        aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

        err = crypto_aead_encrypt(req);
        aead_request_free(req);
        if (err) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }

        {
            static int encap_print_count = 0;
            if (encap_print_count < 5) {
                encap_print_count++;
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: ip_pkt_len=%d, seq=%llu\n", encap_print_count, ip_pkt_len, seq);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: key_len=%d, key=%*phN\n", encap_print_count, cfg->encrypt_key_len, cfg->encrypt_key_len, cfg->encrypt_key);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: salt=%*phN\n", encap_print_count, MWAN_SALT_LEN, cfg->encrypt_salt);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: iv=%*phN\n", encap_print_count, MWAN_GCM_IV_LEN, iv);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: chdr AAD=%*phN\n", encap_print_count, MWAN_CRYPTO_HDR_LEN, chdr);
            }
        }
    }

    skb->ip_summed = CHECKSUM_NONE;

    if (likely(target_dev->real_num_tx_queues > 1)) {
        u16 cpu_id = smp_processor_id();
        u16 q_idx = cpu_id % target_dev->real_num_tx_queues;
        skb_set_queue_mapping(skb, q_idx);
    }

    skb->dev = target_dev;
    skb->protocol = htons(MWAN_L2_PQC_ETHERTYPE);

    rcu_read_unlock();

    dev_queue_xmit(skb);
    return NF_STOLEN;
}
