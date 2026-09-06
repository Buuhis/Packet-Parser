#include "../mwan_steer.h"
#include "../mwan_mac_discovery.h"
#include "../mwan_mtu.h"
#include "../mwan_multicore.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/ip.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 10)
#include <net/gso.h>
#endif

/* Convert the skb to the one representation accepted by the asynchronous
 * TX path: skb->data starts at the IPv4 header and skb->len is exactly
 * iph->tot_len.  The IPv4 classifier has already rejected a truncated skb.
 * Reject trailing bytes instead of silently trimming an ambiguous packet. */
static bool
mwan_none_normalize_ipv4_extent(struct sk_buff *skb,
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

int mwan_encap_none_xmit(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct net_device *target_dev = tun->dev;
    u8 peer_mac[ETH_ALEN];
    int network_offset;

    if (unlikely(!target_dev))
        return -ENODEV;

    if (tun->is_ethernet) {
        if (unlikely(!mwan_mac_get_peer(tun, peer_mac)))
            return -EHOSTUNREACH;

        if (unlikely(skb_headroom(skb) < ETH_HLEN || skb_header_cloned(skb))) {
            if (skb_cow_head(skb, LL_RESERVED_SPACE(target_dev)))
                return -ENOMEM;
        }

        skb_push(skb, ETH_HLEN);
        skb_reset_mac_header(skb);
        {
            struct ethhdr *eth = eth_hdr(skb);
            if (target_dev->dev_addr)
                ether_addr_copy(eth->h_source, target_dev->dev_addr);
            else
                eth_zero_addr(eth->h_source);
            
            ether_addr_copy(eth->h_dest, peer_mac);
            eth->h_proto = htons(ETH_P_IP);
        }
    } else {
        network_offset = skb_network_offset(skb);
        if (network_offset < 0 || network_offset > skb->len)
            return -EINVAL;
        skb_pull(skb, network_offset);
        skb_reset_mac_header(skb);
    }

    if (likely(target_dev->real_num_tx_queues > 1)) {
        u16 cpu_id = smp_processor_id();
        u16 q_idx = cpu_id % target_dev->real_num_tx_queues;
        
        skb_set_queue_mapping(skb, q_idx);
    }

    {
        struct iphdr *iph = ip_hdr(skb);
        if (iph) {
            skb_set_transport_header(skb, skb_network_offset(skb) +
                                           iph->ihl * 4);
        }
    }

    skb->dev = target_dev;
    /* dev_queue_xmit() consumes skb for every return value. */
    dev_queue_xmit(skb);

    return 0;
}

unsigned int mwan_handle_encap_none_direct(struct sk_buff *skb,
                                           struct mwan_tunnel *tun)
{
    return mwan_encap_none_xmit(skb, tun) ? NF_DROP : NF_STOLEN;
}

static bool mwan_none_tcp_closing(struct sk_buff *skb)
{
    struct iphdr iph_buf;
    struct tcphdr tcp_buf;
    const struct iphdr *iph;
    const struct tcphdr *tcp;
    int offset = skb_network_offset(skb);

    if (offset < 0)
        return false;
    iph = skb_header_pointer(skb, offset, sizeof(iph_buf), &iph_buf);
    if (!iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_TCP ||
        (iph->frag_off & htons(IP_OFFSET)))
        return false;
    tcp = skb_header_pointer(skb, offset + iph->ihl * 4,
                             sizeof(tcp_buf), &tcp_buf);
    return tcp && (tcp->fin || tcp->rst);
}

static unsigned int
mwan_handle_encap_none_single(struct sk_buff *skb, struct mwan_config *cfg,
                              u16 tunnel_idx,
                              const struct mwan_tx_flow_context *tx_ctx);

struct mwan_none_fragment_context {
    struct mwan_config *cfg;
    u16 tunnel_idx;
    const struct mwan_tx_flow_context *tx_ctx;
};

static int mwan_none_fragment_output(struct sk_buff *fragment, void *context)
{
    struct mwan_none_fragment_context *fragment_context = context;
    unsigned int verdict;

    verdict = mwan_handle_encap_none_single(
        fragment, fragment_context->cfg, fragment_context->tunnel_idx,
        fragment_context->tx_ctx);
    if (verdict == NF_STOLEN)
        return 0;

    kfree_skb(fragment);
    return -EIO;
}

static unsigned int
mwan_handle_encap_none_single(struct sk_buff *skb, struct mwan_config *cfg,
                              u16 tunnel_idx,
                              const struct mwan_tx_flow_context *tx_ctx)
{
    struct mwan_tx_flow_info local_info;
    const struct mwan_tx_flow_info *info;
    struct mwan_l2_tx_flow *flow = NULL;
    enum mwan_packet_class packet_class;
    struct mwan_tunnel *tun;
    struct mwan_mtu_decision decision;
    enum mwan_mtu_result mtu_result;
    int err;

    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return NF_DROP;
    tun = &cfg->tunnels[tunnel_idx];
    if (!tun->dev)
        return NF_DROP;

    mtu_result = mwan_mtu_classify_ipv4_skb(
        skb, tun->dev, MWAN_MTU_PROFILE_BYPASS, &decision);
    if (mtu_result == MWAN_MTU_OVERSIZE) {
        struct mwan_none_fragment_context fragment_context = {
            .cfg = cfg,
            .tunnel_idx = tunnel_idx,
            .tx_ctx = tx_ctx,
        };
        bool consumed = false;

        if (decision.ipv4_df && !skb->ignore_df) {
            mwan_mtu_send_frag_needed(skb, MWAN_MTU_PROFILE_BYPASS,
                                      &decision);
            return NF_DROP;
        }

        err = mwan_mtu_fragment_ipv4(
            skb, tun->dev, &decision, mwan_none_fragment_output,
            &fragment_context, &consumed);
        if (!consumed) {
            pr_warn_ratelimited("mwan_kmod: bypass MTU fragment setup failed ret=%d\n",
                                err);
            return NF_DROP;
        }
        return NF_STOLEN;
    }
    if (mtu_result != MWAN_MTU_FITS)
        return NF_DROP;
    if (!mwan_none_normalize_ipv4_extent(skb, &decision))
        return NF_DROP;

    if (tx_ctx) {
        info = &tx_ctx->info;
        packet_class = tx_ctx->packet_class;
        flow = mwan_l2_tx_flow_hold(tx_ctx->flow);
        if (!flow)
            return NF_DROP;
    } else {
        mwan_multicore_flow_info(skb, &local_info);
        info = &local_info;
        packet_class = mwan_multicore_packet_classify(skb);
    }
    err = mwan_multicore_tx_submit(skb, cfg, tunnel_idx, info, flow,
                                   packet_class,
                                   mwan_none_tcp_closing(skb), NULL, NULL);
    return err ? NF_DROP : NF_STOLEN;
}

unsigned int mwan_handle_encap_none(struct sk_buff *skb,
                                    struct mwan_config *cfg, u16 tunnel_idx,
                                    const struct mwan_tx_flow_context *tx_ctx)
{
    if (skb_is_gso(skb)) {
        struct sk_buff *segs;
        struct sk_buff *nskb;
        struct sk_buff *next;
        netdev_features_t features = netif_skb_features(skb);

        segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
        if (IS_ERR(segs) || !segs)
            return NF_DROP;
        for (nskb = segs; nskb; nskb = next) {
            next = nskb->next;
            nskb->next = NULL;
            nskb->prev = NULL;
            if (mwan_handle_encap_none_single(nskb, cfg, tunnel_idx,
                                              tx_ctx) !=
                NF_STOLEN)
                kfree_skb(nskb);
        }
        consume_skb(skb);
        return NF_STOLEN;
    }

    return mwan_handle_encap_none_single(skb, cfg, tunnel_idx, tx_ctx);
}
