#include "../mwan_steer.h"
#include "../mwan_mac_discovery.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>
#include <linux/cpu.h>
#include <linux/ktime.h>
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

static bool mwan_l2_extract_ipv4_tuple(struct sk_buff *skb,
                                       struct mwan_l2_tx_diag *diag,
                                       u32 *ports)
{
    struct iphdr iph_buf;
    const struct iphdr *iph;
    __be32 ports_be = 0;
    const __be32 *ports_ptr;
    int network_offset;
    int ip_hlen;

    network_offset = skb_network_offset(skb);
    if (unlikely(network_offset < 0))
        return false;
    iph = skb_header_pointer(skb, network_offset, sizeof(iph_buf), &iph_buf);
    if (unlikely(!iph || iph->version != 4 || iph->ihl < 5))
        return false;

    diag->saddr = iph->saddr;
    diag->daddr = iph->daddr;
    diag->protocol = iph->protocol;
    diag->tuple_valid = true;

    ip_hlen = iph->ihl * 4;
    ports_ptr = NULL;
    if (!(iph->frag_off & htons(IP_MF | IP_OFFSET)) &&
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP))
        ports_ptr = skb_header_pointer(skb, network_offset + ip_hlen,
                                       sizeof(ports_be), &ports_be);
    if (ports_ptr) {
        memcpy(&ports_be, ports_ptr, sizeof(ports_be));
        memcpy(&diag->sport, ports_ptr, sizeof(diag->sport));
        memcpy(&diag->dport, (const u8 *)ports_ptr + sizeof(diag->sport),
               sizeof(diag->dport));
        *ports = (__force u32)ports_be;
    }

    return true;
}

static inline u32 mwan_calc_flow_id(struct sk_buff *skb,
                                    struct mwan_l2_tx_diag *diag)
{
    u32 hash;
    u32 ports = 0;

    memset(diag, 0, sizeof(*diag));
    diag->hash_before = skb_get_hash_raw(skb);
    diag->hash_was_cached = skb->l4_hash || skb->sw_hash;
    diag->hash_is_l4 = skb->l4_hash;
    diag->hash_is_sw = skb->sw_hash;

    /* Use the kernel flow dissector first. At POST_ROUTING this should still
     * identify the plaintext inner flow. Diagnostics record whether this was
     * a pre-existing cached hash or one calculated by the dissector now. */
    hash = skb_get_hash(skb);
    if (likely(hash != 0)) {
        diag->hash_source = diag->hash_was_cached ? "cached" : "dissector";
        mwan_l2_extract_ipv4_tuple(skb, diag, &ports);
        return hash;
    }

    diag->hash_source = "fallback";
    if (!mwan_l2_extract_ipv4_tuple(skb, diag, &ports)) {
        diag->hash_source = "invalid";
        return 0;
    }

    /* Include the L4 protocol so TCP and UDP with the same addresses/ports
     * cannot alias solely because their four-tuple bytes are identical. */
    ports ^= (u32)diag->protocol << 24;
    return jhash_3words((__force u32)diag->saddr,
                        (__force u32)diag->daddr, ports, 0x9e3779b9);
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

/* skb->cb is private to the module from NF_STOLEN until the TX worker clears
 * it. Only metadata moves between CPUs; the packet payload is never copied. */
struct mwan_l2_tx_cb {
    u64 flow_seq;
    u32 flow_id;
    u32 accounted_bytes;
    u16 tunnel_idx;
    u16 magic;
};

#define MWAN_L2_TX_CB_MAGIC 0x4d54U
#define MWAN_L2_TX_CB(skb) ((struct mwan_l2_tx_cb *)((skb)->cb))

static unsigned int
mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun);

static void mwan_l2_tx_update_max(atomic64_t *maximum, u64 value)
{
    s64 old = atomic64_read(maximum);

    while (value > (u64)old) {
        s64 observed = atomic64_cmpxchg(maximum, old, (s64)value);

        if (observed == old)
            break;
        old = observed;
    }
}

static void mwan_l2_tx_update_ewma(struct mwan_l2_worker *worker,
                                   u64 sample_ns)
{
    s64 old;
    s64 next;

    do {
        old = atomic64_read(&worker->tx_processing_ewma_ns);
        next = old ? old - (old >> 3) + ((s64)sample_ns >> 3) : sample_ns;
    } while (atomic64_cmpxchg(&worker->tx_processing_ewma_ns, old, next) !=
             old);
}

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
            nskb->prev = NULL;

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

static int mwan_l2_encrypt_and_xmit(struct sk_buff *skb,
                                    struct mwan_l2_worker *worker,
                                    struct mwan_tunnel *tun, u32 flow_id,
                                    u64 seq)
{
    struct net_device *target_dev = tun->dev;
    struct aead_request *req = worker->tx_req;
    u8 iv[MWAN_RFC4106_IV_LEN];
    u64 packet_nonce;
    __be32 flow_id_be;
    __be64 seq_be, nonce_be;
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

    packet_nonce = mwan_l2_next_packet_nonce();
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

    // Write authenticated L2-PQC header (flow ID, reorder sequence, unique nonce)
    struct mwan_l2_pqc_hdr *l2_hdr = (struct mwan_l2_pqc_hdr *)(skb->data + ETH_HLEN);
    flow_id_be = cpu_to_be32(flow_id);
    seq_be = cpu_to_be64(seq);
    memcpy(&l2_hdr->flow_id, &flow_id_be, sizeof(flow_id_be));
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

static int mwan_l2_tx_enqueue(struct mwan_config *cfg, struct sk_buff *skb,
                              struct mwan_tunnel *tun, u32 flow_id, u64 seq,
                              int *owner_cpu)
{
    struct mwan_l2_tx_flow *flow;
    struct mwan_l2_worker *worker;
    unsigned int accounted_bytes = skb->truesize;
    long tunnel_idx = tun - cfg->tunnels;
    u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
    int owner;
    int new_owner;
    int was_scheduled;

    if (unlikely(tunnel_idx < 0 || tunnel_idx >= cfg->num_tunnels))
        return -EINVAL;

    flow = &cfg->tx_flows[flow_idx];
    spin_lock_bh(&flow->owner_lock);
    owner = atomic_read(&flow->owner_worker);
    if (owner < 0 || owner >= cfg->num_workers) {
        if (unlikely(atomic_read(&flow->pending_crypto) != 0)) {
            spin_unlock_bh(&flow->owner_lock);
            return -EBUSY;
        }
        new_owner = mwan_l2_select_tx_worker(cfg, flow_id, owner);
    } else if (!cpu_online(cfg->l2_workers[owner].cpu)) {
        if (atomic_read(&flow->pending_crypto) != 0) {
            spin_unlock_bh(&flow->owner_lock);
            return -EBUSY;
        }
        new_owner = mwan_l2_select_tx_worker(cfg, flow_id, owner);
    } else {
        /* Never migrate a live TX flow because of load. A worker at or above
         * the high watermark is excluded only from future admissions. */
        new_owner = owner;
    }

    if (new_owner < 0) {
        spin_unlock_bh(&flow->owner_lock);
        return -ENODEV;
    }
    if (new_owner != owner) {
        atomic_set(&flow->owner_worker, new_owner);
        owner = new_owner;
    }

    worker = &cfg->l2_workers[owner];
    if (owner_cpu)
        *owner_cpu = worker->cpu;
    spin_lock(&worker->tx_queue.lock);
    if (worker->tx_queue.qlen >= MWAN_L2_QUEUE_MAX_PACKETS ||
        atomic64_read(&worker->tx_queued_bytes) + accounted_bytes >
            MWAN_L2_QUEUE_MAX_BYTES) {
        spin_unlock(&worker->tx_queue.lock);
        atomic64_inc(&worker->tx_dropped_packets);
        spin_unlock_bh(&flow->owner_lock);
        return -ENOSPC;
    }

    BUILD_BUG_ON(sizeof(struct mwan_l2_tx_cb) > sizeof(skb->cb));
    memset(skb->cb, 0, sizeof(skb->cb));
    MWAN_L2_TX_CB(skb)->flow_seq = seq;
    MWAN_L2_TX_CB(skb)->flow_id = flow_id;
    MWAN_L2_TX_CB(skb)->accounted_bytes = accounted_bytes;
    MWAN_L2_TX_CB(skb)->tunnel_idx = (u16)tunnel_idx;
    MWAN_L2_TX_CB(skb)->magic = MWAN_L2_TX_CB_MAGIC;
    __skb_queue_tail(&worker->tx_queue, skb);
    atomic64_inc(&worker->tx_queued_packets);
    atomic64_add(accounted_bytes, &worker->tx_queued_bytes);
    atomic64_inc(&worker->tx_enqueued_packets);
    atomic_inc(&flow->pending_crypto);
    was_scheduled = atomic_cmpxchg(&worker->tx_scheduled, 0, 1);
    mwan_l2_tx_update_max(&worker->tx_max_queued_packets,
                          worker->tx_queue.qlen);
    mwan_l2_tx_update_max(&worker->tx_max_queued_bytes,
                          atomic64_read(&worker->tx_queued_bytes));
    spin_unlock(&worker->tx_queue.lock);
    spin_unlock_bh(&flow->owner_lock);

    if (was_scheduled == 0 && unlikely(!mwan_l2_schedule_tx_worker(worker)))
        atomic64_inc(&worker->tx_schedule_failures);
    return 0;
}

static unsigned int
mwan_handle_encap_l2_pqc_single(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct mwan_l2_tx_diag flow_diag;
    struct mwan_config *cfg;
    struct net_device *target_dev = tun->dev;
    u32 flow_id;
    u32 flow_idx;
    u64 seq;
    int owner_cpu = -1;
    int err;

    if (unlikely(!target_dev))
        return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (unlikely(!cfg || !cfg->l2_workers || cfg->num_workers <= 0)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* The SYN must be adjusted while the inner packet is still plaintext. */
    mwan_l2_clamp_mss(skb, target_dev);
    flow_id = mwan_calc_flow_id(skb, &flow_diag);
    flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
    seq = mwan_l2_next_tx_seq(flow_idx);
    err = mwan_l2_tx_enqueue(cfg, skb, tun, flow_id, seq, &owner_cpu);
    if (!err)
        mwan_l2_tx_diag_log(&flow_diag, tun, flow_id, flow_idx, seq,
                            owner_cpu);
    rcu_read_unlock();

    return err ? NF_DROP : NF_STOLEN;
}

void mwan_l2_tx_worker_fn(struct work_struct *work)
{
    struct mwan_l2_worker *worker =
        container_of(work, struct mwan_l2_worker, tx_work);
    struct mwan_config *cfg = worker->cfg;
    struct sk_buff *skb;
    unsigned int batch = 0;

    atomic64_inc(&worker->tx_work_runs);
    atomic_set(&worker->tx_busy, 1);
    for (;;) {
        while ((skb = skb_dequeue(&worker->tx_queue)) != NULL) {
            u32 accounted_bytes = MWAN_L2_TX_CB(skb)->accounted_bytes;
            u32 flow_id = MWAN_L2_TX_CB(skb)->flow_id;
            u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
            u64 flow_seq = MWAN_L2_TX_CB(skb)->flow_seq;
            u16 tunnel_idx = MWAN_L2_TX_CB(skb)->tunnel_idx;
            bool cb_ok = MWAN_L2_TX_CB(skb)->magic == MWAN_L2_TX_CB_MAGIC;
            u64 start_ns = ktime_get_ns();
            int err;

            atomic64_dec(&worker->tx_queued_packets);
            atomic64_sub(accounted_bytes, &worker->tx_queued_bytes);
            memset(skb->cb, 0, sizeof(skb->cb));

            if (unlikely(!cb_ok || tunnel_idx >= cfg->num_tunnels))
                err = -EINVAL;
            else
                err = mwan_l2_encrypt_and_xmit(
                    skb, worker, &cfg->tunnels[tunnel_idx], flow_id,
                    flow_seq);

            mwan_l2_tx_update_ewma(worker, ktime_get_ns() - start_ns);
            atomic64_inc(&worker->tx_processed_packets);
            if (unlikely(err)) {
                atomic64_inc(&worker->tx_encrypt_failures);
                atomic64_inc(&worker->tx_dropped_packets);
                kfree_skb(skb);
            }
            atomic_dec(&cfg->tx_flows[flow_idx].pending_crypto);

            if (++batch == 64) {
                batch = 0;
                cond_resched();
            }
        }

        spin_lock_bh(&worker->tx_queue.lock);
        if (!skb_queue_empty(&worker->tx_queue)) {
            spin_unlock_bh(&worker->tx_queue.lock);
            continue;
        }
        atomic_set(&worker->tx_scheduled, 0);
        spin_unlock_bh(&worker->tx_queue.lock);
        break;
    }
    atomic_set(&worker->tx_busy, 0);
}
