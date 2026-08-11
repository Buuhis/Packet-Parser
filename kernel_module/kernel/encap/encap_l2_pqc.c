#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>
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

static inline u32 mwan_calc_flow_id(struct sk_buff *skb)
{
    struct iphdr *iph;
    u32 ports = 0;

    if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
        return 0;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        iph = (struct iphdr *)skb->data;

    if (iph && iph->version == 4 && iph->ihl >= 5) {
        int ip_hlen = iph->ihl * 4;
        if (pskb_may_pull(skb, ip_hlen + 4)) {
            iph = (struct iphdr *)skb->data;
            if (!(iph->frag_off & htons(IP_OFFSET)) &&
                (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
                u8 *l4 = (u8 *)iph + ip_hlen;
                memcpy(&ports, l4, sizeof(ports));
            }
            return jhash_3words((__force u32)iph->saddr, (__force u32)iph->daddr, ports, 0x9e3779b9);
        }
    }
    return 0;
}

/* Performs TCP MSS Clamping to account for the authenticated L2-PQC header
 * and GCM tag carried inside the Ethernet payload.
 * This ensures packets don't exceed MTU after encryption. */
static void mwan_l2_clamp_mss(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u8 *opt;
    int ip_hlen, tcp_hlen, tcp_len, total_len, optlen, i;
    u16 new_mss, old_mss;
    u16 max_mss;

    if (!skb || !dev || skb->protocol != htons(ETH_P_IP))
        return;
    if (dev->mtu <= 40 + MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN)
        return;
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_TCP)
        return;

    ip_hlen = iph->ihl * 4;
    total_len = ntohs(iph->tot_len);
    if (total_len < ip_hlen + sizeof(struct tcphdr) || total_len > skb->len)
        return;
    if (!pskb_may_pull(skb, total_len))
        return;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + ip_hlen);
    if (!tcph->syn || tcph->doff < 5)
        return;

    tcp_hlen = tcph->doff * 4;
    tcp_len = total_len - ip_hlen;
    if (tcp_hlen > tcp_len)
        return;

    max_mss = dev->mtu - 40 - MWAN_L2_HDR_LEN - MWAN_GCM_TAG_LEN;
    optlen = tcp_hlen - sizeof(struct tcphdr);
    opt = (u8 *)(tcph + 1);

    for (i = 0; i < optlen; ) {
        if (opt[i] == TCPOPT_EOL) break;
        if (opt[i] == TCPOPT_NOP) { i++; continue; }
        if (i + 1 >= optlen || i + opt[i + 1] > optlen) break;

        if (opt[i] == TCPOPT_MSS && opt[i + 1] == TCPOLEN_MSS) {
            old_mss = (opt[i + 2] << 8) | opt[i + 3];
            if (old_mss > max_mss) {
                new_mss = max_mss;
                if (skb_ensure_writable(skb, total_len))
                    return;
                iph = ip_hdr(skb);
                tcph = (struct tcphdr *)((u8 *)iph + ip_hlen);
                opt = (u8 *)(tcph + 1);
                opt[i + 2] = (new_mss >> 8) & 0xFF;
                opt[i + 3] = new_mss & 0xFF;
                /* CHECKSUM_PARTIAL still contains an offload seed and will be
                 * completed once below. Other packets already carry a full
                 * checksum, so adjust only the changed 16-bit MSS word. */
                if (skb->ip_summed != CHECKSUM_PARTIAL)
                    csum_replace2(&tcph->check, htons(old_mss), htons(new_mss));
            }
            break;
        }
        i += opt[i + 1];
    }
}

static unsigned int mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun);

unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    if (skb_is_gso(skb)) {
        struct sk_buff *segs, *nskb, *next;
        netdev_features_t features = netif_skb_features(skb);

        /* Force software segmentation by clearing all GSO features.
         * This splits 64KB GSO super-packets into MTU-compliant SKBs */
        segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
        if (IS_ERR(segs) || !segs) {
            return NF_DROP;
        }

        nskb = segs;
        while (nskb) {
            next = nskb->next;
            nskb->next = NULL;

            if (mwan_handle_encap_l2_pqc(nskb, tun) != NF_STOLEN) {
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
    u8 iv[MWAN_RFC4106_IV_LEN];
    u64 packet_nonce;
    __be32 flow_id_be;
    __be64 seq_be, nonce_be;
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

    /* Clamp TCP MSS on SYN packets before encryption */
    mwan_l2_clamp_mss(skb, target_dev);

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
    skb_reset_network_header(skb);

    // Fast-path MAC resolution: only resolve if MAC is not cached yet or invalid
    if (tun->is_ethernet && unlikely(!tun->mac_resolved)) {
        resolved = mwan_resolve_gateway_mac(tun, target_dev, tun->gateway_mac);
        if (unlikely(!resolved)) {
            rcu_read_unlock();
            return NF_DROP;
        }
        tun->mac_resolved = true;
    }

    /* Only run skb_checksum_help if checksum is partial (locally generated packet).
     * For forwarded packets, original TCP/UDP checksum is already complete. */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb)) {
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    u32 flow_id = mwan_calc_flow_id(skb);
    u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
    seq = mwan_l2_next_tx_seq(flow_idx);
    packet_nonce = mwan_l2_next_packet_nonce();
    if (unlikely(packet_nonce == 0)) {
        rcu_read_unlock();
        return NF_DROP;
    }
    nonce_be = cpu_to_be64(packet_nonce);
    memcpy(iv, &nonce_be, sizeof(nonce_be));

    // Expand skb headroom/tailroom for Ethernet header + L2-PQC header + tag
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

    // Prepend Ethernet and the 20-byte L2-PQC RFC4106 prefix.
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

    // Write authenticated L2-PQC header (flow ID, reorder sequence, unique nonce)
    struct mwan_l2_pqc_hdr *l2_hdr = (struct mwan_l2_pqc_hdr *)(skb->data + ETH_HLEN);
    flow_id_be = cpu_to_be32(flow_id);
    seq_be = cpu_to_be64(seq);
    memcpy(&l2_hdr->flow_id, &flow_id_be, sizeof(flow_id_be));
    memcpy(&l2_hdr->flow_seq, &seq_be, sizeof(seq_be));
    memcpy(&l2_hdr->packet_nonce, &nonce_be, sizeof(nonce_be));

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
        /* RFC4106 consumes 12 authenticated bytes followed by its 8-byte
         * explicit IV, for a total associated-data prefix of 20 bytes. */
        sg_set_buf(&sg[0], (u8 *)l2_hdr, MWAN_L2_HDR_LEN);

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
