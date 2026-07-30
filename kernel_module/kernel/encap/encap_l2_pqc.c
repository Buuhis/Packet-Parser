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
#include <linux/jhash.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#define MWAN_L2_HDR_LEN 16 /* 16 Bytes AAD for RFC4106 */

static unsigned int mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun);

static void mwan_tx_worker_func(struct work_struct *w)
{
    struct mwan_tx_work *work = container_of(w, struct mwan_tx_work, work);
    struct sk_buff *skb = work->skb;
    struct mwan_tunnel tun = work->tun;

    mwan_handle_encap_l2_pqc_single(skb, &tun);
    kfree(work);
}

/* Helper to update TCP checksum after MSS modification */
static inline void mwan_l2_tcp_update_csum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    int tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                                    csum_partial(tcph, tcplen, 0));
}

/* Performs TCP MSS Clamping to account for L2-PQC 24-byte encryption overhead.
 * This ensures packets don't exceed MTU after encryption. */
static void mwan_l2_clamp_mss(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u8 *opt;
    int optlen, i;
    u16 new_mss, old_mss;
    u16 max_mss = dev->mtu - 40 - (ETH_HLEN + MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN); 

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
                mwan_l2_tcp_update_csum(skb, iph, tcph);
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

    struct mwan_config *cfg;
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && cfg->encrypt_on && cfg->tx_wq && cfg->num_workers > 1) {
        u32 hash = skb_get_hash(skb);
        if (hash == 0 && skb->len >= sizeof(struct iphdr)) {
            struct iphdr *iph = ip_hdr(skb);
            if (iph && iph->version == 4) {
                u16 sport = 0, dport = 0;
                if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
                    u16 *ports = (u16 *)((u8 *)iph + (iph->ihl * 4));
                    sport = ports[0];
                    dport = ports[1];
                }
                hash = jhash_3words(iph->saddr, iph->daddr, ((u32)sport << 16) | dport, iph->protocol);
            }
        }

        int target_worker_idx = hash % cfg->num_workers;
        int target_cpu = cfg->worker_start_cpu + target_worker_idx;
        struct workqueue_struct *wq = cfg->tx_wq;
        rcu_read_unlock();

        struct mwan_tx_work *work = kmalloc(sizeof(*work), GFP_ATOMIC);
        if (work) {
            INIT_WORK(&work->work, mwan_tx_worker_func);
            work->skb = skb;
            work->tun = *tun;
            work->target_cpu = target_cpu;
            queue_work_on(target_cpu, wq, &work->work);
            return NF_STOLEN;
        }
    } else {
        rcu_read_unlock();
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

    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    *(__be64 *)iv = cpu_to_be64(seq);

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

    // Write 16-byte L2 Header (8B Sequence Number + 8B Reserved) for RFC4106 AAD=16
    seq_hdr = (__be64 *)(skb->data + ETH_HLEN);
    seq_hdr[0] = cpu_to_be64(seq);
    seq_hdr[1] = 0;

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
        sg_set_buf(&sg[0], (u8 *)seq_hdr, MWAN_L2_HDR_LEN); // AAD = 16B for RFC4106

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
