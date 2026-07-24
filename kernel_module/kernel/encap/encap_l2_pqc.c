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

#define MWAN_L2_HDR_LEN 8 /* 8 Bytes Sequence Number */

unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct mwan_config *cfg;
    struct net_device *target_dev = tun->dev;
    struct crypto_aead *tfm;
    struct aead_request *req;
    u8 iv[MWAN_GCM_IV_LEN];
    __be64 *seq_hdr;
    u64 seq;
    int ip_pkt_len, err;
    bool resolved;

    if (unlikely(!target_dev)) {
        return NF_ACCEPT;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (unlikely(!cfg || !cfg->tfm)) {
        rcu_read_unlock();
        return NF_ACCEPT;
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
            return NF_DROP;
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

    /* Only run skb_checksum_help if checksum is partial (locally generated packet).
     * For forwarded packets, original TCP/UDP checksum is already complete. */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb)) {
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    memcpy(iv, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv + MWAN_SALT_LEN) = cpu_to_be64(seq);

    // Expand skb headroom/tailroom for Ethernet header + 8B Seq + Tag
    if (skb_cow(skb, LL_RESERVED_SPACE(target_dev) + ETH_HLEN + MWAN_L2_HDR_LEN)) {
        rcu_read_unlock();
        return NF_DROP;
    }
    if (skb_tailroom(skb) < MWAN_GCM_TAG_LEN) {
        if (pskb_expand_head(skb, 0, MWAN_GCM_TAG_LEN, GFP_ATOMIC)) {
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    // Prepend Ethernet (14B) + Seq Header (8B)
    skb_push(skb, ETH_HLEN + MWAN_L2_HDR_LEN);
    skb_reset_mac_header(skb);

    // Write Ethernet Header
    struct ethhdr *eth = eth_hdr(skb);
    if (target_dev->dev_addr)
        ether_addr_copy(eth->h_source, target_dev->dev_addr);
    else
        eth_zero_addr(eth->h_source);
    
    if (tun->is_ethernet)
        ether_addr_copy(eth->h_dest, tun->gateway_mac);
    else
        eth_zero_addr(eth->h_dest);
    eth->h_proto = htons(MWAN_L2_PQC_ETHERTYPE);

    // Write 8-byte Sequence Header
    seq_hdr = (__be64 *)(skb->data + ETH_HLEN);
    *seq_hdr = cpu_to_be64(seq);

    // Put Tag space at the tail
    skb_put(skb, MWAN_GCM_TAG_LEN);

    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        return NF_DROP;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], (u8 *)seq_hdr, MWAN_L2_HDR_LEN); // AAD = 8B Seq

        nents = skb_to_sgvec(skb, &sg[1], ETH_HLEN + MWAN_L2_HDR_LEN, ip_pkt_len + MWAN_GCM_TAG_LEN);
        if (unlikely(nents < 0)) {
            aead_request_free(req);
            rcu_read_unlock();
            return NF_DROP;
        }

        aead_request_set_crypt(req, sg, sg, ip_pkt_len, iv);
        aead_request_set_ad(req, MWAN_L2_HDR_LEN);

        err = crypto_aead_encrypt(req);
        aead_request_free(req);
        if (err) {
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    skb->ip_summed = CHECKSUM_NONE;
    skb_shinfo(skb)->gso_size = 0;
    skb_shinfo(skb)->gso_type = 0;
    skb_shinfo(skb)->gso_segs = 0;
    skb->encapsulation = 0;

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
