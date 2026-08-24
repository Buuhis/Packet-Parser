#include "../mwan_steer.h"
#include "../mwan_mac_discovery.h"
#include "../mwan_mtu.h"
#include "../mwan_multicore.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/cpu.h>
#include <linux/ktime.h>
#include <net/neighbour.h>
#include <net/ip.h>
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

struct mwan_l2_tx_diag {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u32 hash_before;
    u8 protocol;
    bool tuple_valid;
    bool hash_was_cached;
    bool hash_is_l4;
    bool hash_is_sw;
    const char *hash_source;
};

struct mwan_l2_tx_diag_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u32 flow_id;
    u8 protocol;
    bool tuple_valid;
};

static DEFINE_SPINLOCK(mwan_l2_tx_diag_lock);
static struct mwan_l2_tx_diag_key
    mwan_l2_tx_diag_flows[MWAN_L2_DIAG_MAX_FLOWS];
static unsigned int mwan_l2_tx_diag_count;
static atomic64_t mwan_l2_tx_diag_flow_count;
static atomic64_t mwan_l2_tx_diag_zero;

/* The crypto worker must see only the IPv4 datagram.  Classification uses
 * iph->tot_len, whereas AEAD encrypts skb->len, so accepting trailing bytes
 * here would encrypt and transmit data that is outside the IPv4 packet. */
static bool
mwan_l2_normalize_ipv4_extent(struct sk_buff *skb,
                              const struct mwan_mtu_decision *decision)
{
    int network_offset;
    u32 extent;

    if (!skb || !decision || !decision->inner_len ||
        decision->ipv4_header_len < sizeof(struct iphdr))
        return false;

    network_offset = skb_network_offset(skb);
    if (network_offset < 0 || (u32)network_offset > skb->len)
        return false;
    if (decision->inner_len > skb->len - (u32)network_offset)
        return false;

    extent = (u32)network_offset + decision->inner_len;
    if (extent != skb->len)
        return false;
    if (!pskb_may_pull(skb, network_offset +
                            decision->ipv4_header_len))
        return false;
    if (network_offset) {
        const u8 *prefix = skb->data;

        if (!skb_pull(skb, network_offset))
            return false;
        skb_postpull_rcsum(skb, prefix, network_offset);
    }

    skb_reset_network_header(skb);
    return skb->len == decision->inner_len;
}

void mwan_l2_tx_diag_reset(void)
{
    spin_lock_bh(&mwan_l2_tx_diag_lock);
    memset(mwan_l2_tx_diag_flows, 0, sizeof(mwan_l2_tx_diag_flows));
    mwan_l2_tx_diag_count = 0;
    spin_unlock_bh(&mwan_l2_tx_diag_lock);
    atomic64_set(&mwan_l2_tx_diag_flow_count, 0);
    atomic64_set(&mwan_l2_tx_diag_zero, 0);
}

u64 mwan_l2_tx_diag_flows_get(void)
{
    return atomic64_read(&mwan_l2_tx_diag_flow_count);
}

u64 mwan_l2_tx_diag_zero_get(void)
{
    return atomic64_read(&mwan_l2_tx_diag_zero);
}

static bool mwan_l2_tx_diag_first_flow(u32 flow_id,
                                       const struct mwan_l2_tx_diag *diag)
{
    struct mwan_l2_tx_diag_key key = {
        .saddr = diag->saddr,
        .daddr = diag->daddr,
        .sport = diag->sport,
        .dport = diag->dport,
        .flow_id = flow_id,
        .protocol = diag->protocol,
        .tuple_valid = diag->tuple_valid,
    };
    unsigned int count;
    unsigned int limit;
    unsigned int i;
    bool first = false;

    if (!READ_ONCE(mwan_l2_diag_enabled))
        return false;

    limit = min_t(unsigned int, READ_ONCE(mwan_l2_diag_limit),
                  MWAN_L2_DIAG_MAX_FLOWS);
    spin_lock_bh(&mwan_l2_tx_diag_lock);
    count = mwan_l2_tx_diag_count;
    for (i = 0; i < count; i++) {
        const struct mwan_l2_tx_diag_key *seen = &mwan_l2_tx_diag_flows[i];

        if (key.tuple_valid && seen->tuple_valid &&
            key.saddr == seen->saddr && key.daddr == seen->daddr &&
            key.sport == seen->sport && key.dport == seen->dport &&
            key.protocol == seen->protocol)
            goto out;
        if (!key.tuple_valid && !seen->tuple_valid &&
            key.flow_id == seen->flow_id)
            goto out;
    }
    if (count < limit) {
        mwan_l2_tx_diag_flows[count] = key;
        mwan_l2_tx_diag_count = count + 1;
        atomic64_inc(&mwan_l2_tx_diag_flow_count);
        first = true;
    }
out:
    spin_unlock_bh(&mwan_l2_tx_diag_lock);
    return first;
}

static void mwan_l2_tx_diag_log(const struct mwan_l2_tx_diag *diag,
                                const struct mwan_tunnel *tun, u32 flow_id,
                                u32 flow_idx, u64 flow_seq, int owner_cpu)
{
    bool first;
    u32 generation;

    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    generation = mwan_l2_diag_generation_get();
    first = mwan_l2_tx_diag_first_flow(flow_id, diag);

    if (unlikely(flow_id == 0)) {
        atomic64_inc(&mwan_l2_tx_diag_zero);
        if (diag->tuple_valid)
            pr_info_ratelimited("mwan_kmod: L2D TX_ZERO g=%u seq=%llu tuple=%pI4:%u>%pI4:%u p=%u hs=%s raw=%08x dispatch=%u owner_cpu=%d tun=%s\n",
                                generation, flow_seq, &diag->saddr,
                                ntohs(diag->sport), &diag->daddr,
                                ntohs(diag->dport), diag->protocol,
                                diag->hash_source, diag->hash_before,
                                raw_smp_processor_id(), owner_cpu,
                                tun->dev ? tun->dev->name : "none");
        else
            pr_info_ratelimited("mwan_kmod: L2D TX_ZERO g=%u seq=%llu tuple=invalid hs=%s raw=%08x dispatch=%u owner_cpu=%d tun=%s\n",
                                generation, flow_seq, diag->hash_source,
                                diag->hash_before, raw_smp_processor_id(),
                                owner_cpu,
                                tun->dev ? tun->dev->name : "none");
        return;
    }

    if (!first)
        return;

    if (diag->tuple_valid) {
        pr_info("mwan_kmod: L2D TX g=%u f=%08x b=%u seq=%llu tuple=%pI4:%u>%pI4:%u p=%u hs=%s raw=%08x dispatch=%u owner_cpu=%d tun=%s\n",
                generation, flow_id, flow_idx, flow_seq, &diag->saddr,
                ntohs(diag->sport), &diag->daddr, ntohs(diag->dport),
                diag->protocol, diag->hash_source, diag->hash_before,
                raw_smp_processor_id(), owner_cpu,
                tun->dev ? tun->dev->name : "none");
    } else {
        pr_info("mwan_kmod: L2D TX g=%u f=%08x b=%u seq=%llu tuple=invalid hs=%s raw=%08x dispatch=%u owner_cpu=%d tun=%s\n",
                generation, flow_id, flow_idx, flow_seq, diag->hash_source,
                diag->hash_before, raw_smp_processor_id(), owner_cpu,
                tun->dev ? tun->dev->name : "none");
    }
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
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_TCP ||
        (iph->frag_off & htons(IP_OFFSET)))
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

    max_mss = mwan_mtu_ipv4_l4_payload_limit(
        dev, MWAN_MTU_PROFILE_L2_PQC, sizeof(struct iphdr),
        sizeof(struct tcphdr));
    if (!max_mss)
        return;
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

static unsigned int
mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_config *cfg,
                                u16 tunnel_idx);

struct mwan_l2_fragment_context {
    struct mwan_config *cfg;
    u16 tunnel_idx;
    /* ip_do_fragment() removes the UDP header from every non-initial
     * fragment and marks the first one with IP_MF.  Preserve the flow
     * identity extracted from the complete datagram so all fragments keep
     * the original 4-tuple and owner worker. */
    struct mwan_tx_flow_info flow_info;
    bool preserve_flow;
};

static int
mwan_l2_submit_fragment(struct sk_buff *fragment,
                        struct mwan_l2_fragment_context *fragment_context)
{
    struct mwan_l2_tx_diag flow_diag;
    struct mwan_mtu_decision decision;
    struct mwan_tunnel *tun;
    enum mwan_mtu_result mtu_result;
    u32 flow_idx;
    u32 seq = 0;
    int owner_cpu = -1;
    int err;

    if (!fragment || !fragment_context || !fragment_context->cfg ||
        fragment_context->tunnel_idx >= fragment_context->cfg->num_tunnels)
        return -EINVAL;

    tun = &fragment_context->cfg->tunnels[fragment_context->tunnel_idx];
    if (!tun->dev)
        return -ENODEV;

    /* The kernel fragmenter was given the effective L2-PQC inner MTU.  Do
     * not recurse through the oversize path or recalculate the flow from a
     * fragment that no longer contains the complete UDP 4-tuple. */
    mtu_result = mwan_mtu_classify_ipv4_skb(
        fragment, tun->dev, MWAN_MTU_PROFILE_L2_PQC, &decision);
    if (mtu_result != MWAN_MTU_FITS)
        return mtu_result == MWAN_MTU_OVERSIZE ? -EMSGSIZE : -EINVAL;
    if (!mwan_l2_normalize_ipv4_extent(fragment, &decision))
        return -EINVAL;

    err = mwan_multicore_tx_submit(
        fragment, fragment_context->cfg, fragment_context->tunnel_idx,
        &fragment_context->flow_info, false, &seq, &owner_cpu);
    if (err)
        return err;

    memset(&flow_diag, 0, sizeof(flow_diag));
    flow_diag.saddr = fragment_context->flow_info.key.saddr;
    flow_diag.daddr = fragment_context->flow_info.key.daddr;
    flow_diag.sport = fragment_context->flow_info.key.sport;
    flow_diag.dport = fragment_context->flow_info.key.dport;
    flow_diag.protocol = fragment_context->flow_info.key.protocol;
    flow_diag.hash_before = fragment_context->flow_info.hash_before;
    flow_diag.tuple_valid = fragment_context->flow_info.tuple_valid;
    flow_diag.hash_was_cached =
        fragment_context->flow_info.hash_was_cached;
    flow_diag.hash_is_l4 = fragment_context->flow_info.hash_is_l4;
    flow_diag.hash_is_sw = fragment_context->flow_info.hash_is_sw;
    flow_diag.hash_source = mwan_multicore_hash_source_name(
        fragment_context->flow_info.hash_source);
    flow_idx = fragment_context->flow_info.flow_id &
               (MWAN_FLOW_HASH_SIZE - 1);
    mwan_l2_tx_diag_log(&flow_diag, tun,
                        fragment_context->flow_info.flow_id, flow_idx, seq,
                        owner_cpu);
    return 0;
}

static int mwan_l2_fragment_output(struct sk_buff *fragment, void *context)
{
    struct mwan_l2_fragment_context *fragment_context = context;
    unsigned int verdict;
    int err;

    if (unlikely(!fragment_context)) {
        kfree_skb(fragment);
        return -EINVAL;
    }

    if (fragment_context->preserve_flow) {
        err = mwan_l2_submit_fragment(fragment, fragment_context);
        if (!err)
            return 0;

        kfree_skb(fragment);
        return err;
    }

    verdict = mwan_handle_encap_l2_pqc_single(
        fragment, fragment_context->cfg, fragment_context->tunnel_idx);
    if (verdict == NF_STOLEN)
        return 0;

    kfree_skb(fragment);
    return -EIO;
}

unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb,
                                      struct mwan_config *cfg,
                                      u16 tunnel_idx)
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
            nskb->prev = NULL;

            if (mwan_handle_encap_l2_pqc_single(nskb, cfg, tunnel_idx) !=
                NF_STOLEN) {
                kfree_skb(nskb);
            }

            nskb = next;
        }
        consume_skb(skb);
        return NF_STOLEN;
    }

    return mwan_handle_encap_l2_pqc_single(skb, cfg, tunnel_idx);
}

int mwan_l2_pqc_encrypt_xmit(struct sk_buff *skb,
                             struct mwan_l2_worker *worker,
                             struct mwan_tunnel *tun, u64 flow_token,
                             u32 seq)
{
    struct net_device *target_dev = tun->dev;
    struct aead_request *req = worker->tx_req;
    u8 iv[MWAN_RFC4106_IV_LEN];
    u64 packet_nonce;
    __be64 flow_token_be, nonce_be;
    __be32 seq_be;
    u8 peer_mac[ETH_ALEN];
    int ip_pkt_len, err;

    if (unlikely(!target_dev || !worker->tx_tfm || !req))
        return -ENODEV;
    if (unlikely(!tun->is_ethernet))
        return -EAFNOSUPPORT;
    if (unlikely(!mwan_mac_get_peer(tun, peer_mac)))
        return -EHOSTUNREACH;
    ip_pkt_len = skb->len;
    if (ip_pkt_len <= 0)
        return -EINVAL;

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb)))
            return -ENOMEM;
    }
    skb_reset_network_header(skb);

    /* Only run skb_checksum_help if checksum is partial (locally generated packet).
     * For forwarded packets, original TCP/UDP checksum is already complete. */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb))
            return -EINVAL;
    }

    packet_nonce = mwan_next_packet_nonce();
    if (unlikely(packet_nonce == 0))
        return -EOVERFLOW;
    nonce_be = cpu_to_be64(packet_nonce);
    memcpy(iv, &nonce_be, sizeof(nonce_be));

    // Expand skb headroom/tailroom for Ethernet header + L2-PQC header + tag
    if (skb_cow(skb, LL_RESERVED_SPACE(target_dev) + ETH_HLEN +
                MWAN_L2_HDR_LEN))
        return -ENOMEM;
    if (skb_tailroom(skb) < MWAN_GCM_TAG_LEN) {
        if (pskb_expand_head(skb, 0, MWAN_GCM_TAG_LEN, GFP_ATOMIC))
            return -ENOMEM;
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
    
    ether_addr_copy(eth->h_dest, peer_mac);
    eth->h_proto = htons(MWAN_L2_PQC_ETHERTYPE);

    // Write authenticated L2-PQC header (connection cookie, sequence, nonce)
    struct mwan_l2_pqc_hdr *l2_hdr = (struct mwan_l2_pqc_hdr *)(skb->data + ETH_HLEN);
    flow_token_be = cpu_to_be64(flow_token);
    seq_be = cpu_to_be32(seq);
    memcpy(&l2_hdr->flow_token, &flow_token_be, sizeof(flow_token_be));
    memcpy(&l2_hdr->flow_seq, &seq_be, sizeof(seq_be));
    memcpy(&l2_hdr->packet_nonce, &nonce_be, sizeof(nonce_be));

    // Put Tag space at the tail
    skb_put(skb, MWAN_GCM_TAG_LEN);

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        /* RFC4106 consumes 12 authenticated bytes followed by its 8-byte
         * explicit IV, for a total associated-data prefix of 20 bytes. */
        sg_set_buf(&sg[0], (u8 *)l2_hdr, MWAN_L2_HDR_LEN);

        nents = skb_to_sgvec(skb, &sg[1], ETH_HLEN + MWAN_L2_HDR_LEN, ip_pkt_len + MWAN_GCM_TAG_LEN);
        if (unlikely(nents < 0))
            return nents;

        aead_request_set_crypt(req, sg, sg, ip_pkt_len, iv);
        aead_request_set_ad(req, MWAN_L2_HDR_LEN);

        err = crypto_aead_encrypt(req);
        if (err)
            return err;
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

    dev_queue_xmit(skb);
    return 0;
}

static bool mwan_l2_tcp_flow_closing(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    int offset;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_TCP ||
        (iph->frag_off & htons(IP_OFFSET)))
        return false;
    offset = iph->ihl * 4;
    if (!pskb_may_pull(skb, offset + sizeof(*tcph)))
        return false;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + offset);
    return tcph->fin || tcph->rst;
}

static unsigned int
mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_config *cfg,
                                u16 tunnel_idx)
{
    struct mwan_tx_flow_info info;
    struct mwan_l2_tx_diag flow_diag;
    struct mwan_mtu_decision decision;
    struct mwan_tunnel *tun;
    struct net_device *target_dev;
    enum mwan_mtu_result mtu_result;
    u32 flow_id;
    u32 flow_idx;
    u32 seq = 0;
    int owner_cpu = -1;
    int err;

    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return NF_DROP;
    tun = &cfg->tunnels[tunnel_idx];
    target_dev = tun->dev;
    if (unlikely(!target_dev))
        return NF_DROP;

    mtu_result = mwan_mtu_classify_ipv4_skb(
        skb, target_dev, MWAN_MTU_PROFILE_L2_PQC, &decision);
    if (mtu_result == MWAN_MTU_OVERSIZE) {
        struct mwan_l2_fragment_context fragment_context = {
            .cfg = cfg,
            .tunnel_idx = tunnel_idx,
        };
        bool consumed = false;

        if (decision.ipv4_df && !skb->ignore_df) {
            mwan_mtu_send_frag_needed(skb, MWAN_MTU_PROFILE_L2_PQC,
                                      &decision);
            return NF_DROP;
        }

        /* skb_gso_segment() has already run in the wrapper.  A normal UDP
         * datagram reaches this branch with its complete 4-tuple still
         * available, so capture it before ip_do_fragment() creates packets
         * whose IP fragment flags intentionally hide the L4 ports from the
         * generic flow dissector. */
        if (decision.ip_protocol == IPPROTO_UDP) {
            mwan_multicore_flow_info(skb, &fragment_context.flow_info);
            fragment_context.preserve_flow = true;
        }

        err = mwan_mtu_fragment_ipv4(
            skb, target_dev, &decision, mwan_l2_fragment_output,
            &fragment_context, &consumed);
        if (!consumed) {
            pr_warn_ratelimited("mwan_kmod: L2-PQC MTU fragment setup failed ret=%d\n",
                                err);
            return NF_DROP;
        }
        return NF_STOLEN;
    }
    if (mtu_result != MWAN_MTU_FITS)
        return NF_DROP;
    if (!mwan_l2_normalize_ipv4_extent(skb, &decision))
        return NF_DROP;

    /* The SYN must be adjusted while the normalized inner packet is still
     * plaintext. */
    mwan_l2_clamp_mss(skb, target_dev);

    flow_id = mwan_multicore_flow_info(skb, &info);
    memset(&flow_diag, 0, sizeof(flow_diag));
    flow_diag.saddr = info.key.saddr;
    flow_diag.daddr = info.key.daddr;
    flow_diag.sport = info.key.sport;
    flow_diag.dport = info.key.dport;
    flow_diag.protocol = info.key.protocol;
    flow_diag.hash_before = info.hash_before;
    flow_diag.tuple_valid = info.tuple_valid;
    flow_diag.hash_was_cached = info.hash_was_cached;
    flow_diag.hash_is_l4 = info.hash_is_l4;
    flow_diag.hash_is_sw = info.hash_is_sw;
    flow_diag.hash_source =
        mwan_multicore_hash_source_name(info.hash_source);
    flow_idx = flow_id & (MWAN_FLOW_HASH_SIZE - 1);
    err = mwan_multicore_tx_submit(skb, cfg, tunnel_idx, &info,
                                   mwan_l2_tcp_flow_closing(skb), &seq,
                                   &owner_cpu);
    if (!err)
        mwan_l2_tx_diag_log(&flow_diag, tun, flow_id, flow_idx, seq,
                            owner_cpu);

    return err ? NF_DROP : NF_STOLEN;
}
