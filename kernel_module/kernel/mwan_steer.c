#include "mwan_steer.h"
#include "mwan_state.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>

/*
 * mwan_steer - Hàm chọn tunnel và gán rtable mới.
 *
 * Được gọi từ cả PRE_ROUTING (cho Forwarded traffic) và LOCAL_OUT (cho traffic
 * phát sinh từ chính server, ví dụ: lệnh ping trực tiếp trên server).
 *
 * Cơ chế:
 *   1. Kiểm tra IP đích có thuộc Overlay CIDR không.
 *   2. Hash 5-tuple → chọn tunnel theo weight.
 *   3. Tra cứu rtable tới GATEWAY của tunnel đó với RT_SCOPE_LINK:
 *      - Kernel luôn có connected-route cho Gateway vì interface đã được gán IP
 *        trên cùng lớp mạng → tra cứu KHÔNG bao giờ bị fallback về default route.
 *   4. Kiểm tra interface trả về phải khớp với interface mục tiêu.
 *   5. Gán rtable mới vào gói tin (skb_dst_set).
 *   6. Trả NF_ACCEPT → Kernel tự hoàn thiện:
 *      - ip_finish_output2() tra ARP dựa trên rtable mới → gắn đúng MAC gateway
 *      - ip_fragment() xử lý MTU tự động
 *      - ip_send_check() tính lại checksum
 */
static unsigned int mwan_do_steer(struct sk_buff *skb, struct net *net)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    int target_ifindex = 0;
    __be32 gateway = 0;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);

    if (!cfg || cfg->num_tunnels == 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Filter: Chỉ xử lý traffic đến Overlay CIDR */
    if ((iph->daddr & cfg->cidr_mask) != (cfg->cidr_ip & cfg->cidr_mask)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 2. Hash 5-tuple để đảm bảo cùng flow → cùng tunnel */
    {
        u32 ports = 0;
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            unsigned int offset = iph->ihl * 4;
            if (skb_headlen(skb) >= offset + 4)
                ports = *(__be32 *)(skb_network_header(skb) + offset);
        }
        hash = jhash_3words((__force u32)iph->saddr, (__force u32)iph->daddr,
                            (iph->protocol << 16) | (ports & 0xFFFF), 0x12345678);
    }

    /* 3. Chọn tunnel theo hash + weight */
    {
        u32 total_weight = 0;
        int i;

        for (i = 0; i < cfg->num_tunnels; i++)
            total_weight += cfg->tunnels[i].weight;

        if (total_weight > 0) {
            u32 target_slot = hash % total_weight;
            u32 current_sum = 0;
            for (i = 0; i < cfg->num_tunnels; i++) {
                current_sum += cfg->tunnels[i].weight;
                if (target_slot < current_sum) {
                    target_ifindex = cfg->tunnels[i].ifindex;
                    gateway       = cfg->tunnels[i].gateway;
                    break;
                }
            }
        }
    }
    rcu_read_unlock();

    if (target_ifindex == 0 || gateway == 0)
        return NF_ACCEPT;

    /*
     * 4. Tra cứu rtable tới GATEWAY trên interface mục tiêu.
     *
     * Dùng .daddr = gateway (ví dụ 131.1) thay vì IP đích cuối cùng (8.8.8.8).
     * Dùng RT_SCOPE_LINK để ép tìm trong lớp mạng cục bộ của interface 131.0.
     *
     * Ngay cả khi hệ thống không có default route qua 131.0,
     * interface 131.0 vẫn luôn có connected-route nội bộ cho lớp 131.0/24 của nó
     * → tra cứu này luôn thành công và KHÔNG bao giờ fallback về interface 11.0.
     */
    {
        struct flowi4 fl4 = {
            .daddr        = gateway,
            .saddr        = 0,
            .flowi4_oif   = target_ifindex,
            .flowi4_tos   = RT_TOS(iph->tos),
            .flowi4_scope = RT_SCOPE_LINK,
            .flowi4_flags = FLOWI_FLAG_ANYSRC,
        };
        struct rtable *rt = ip_route_output_key(net, &fl4);

        if (IS_ERR(rt)) {
            pr_warn_ratelimited("mwan_kmod: route lookup failed for gw %pI4 on ifindex %u (err=%ld)\n",
                                &gateway, target_ifindex, PTR_ERR(rt));
            return NF_ACCEPT;
        }

        /* 5. Kiểm tra Kernel có trả về đúng interface không */
        if (rt->dst.dev->ifindex != target_ifindex) {
            pr_warn_ratelimited("mwan_kmod: route for gw %pI4 returned %s, expected ifindex %u — skipping\n",
                                &gateway, rt->dst.dev->name, target_ifindex);
            ip_rt_put(rt);
            return NF_ACCEPT;
        }

        /*
         * 6. Gán rtable mới vào gói tin.
         *
         * Từ đây, ip_finish_output2() sẽ đọc rtable này để:
         *   - Biết interface đích là 131.0
         *   - Tra ARP cho Gateway 131.1 → lấy đúng MAC
         *   - Không bao giờ dùng MAC của 11.1 nữa
         */
        skb_dst_drop(skb);
        skb_dst_set(skb, &rt->dst);
        skb->dev = rt->dst.dev;
        skb_clear_hash(skb);

        pr_debug("mwan_kmod: steered %pI4→%pI4 via %s (gw %pI4)\n",
                 &iph->saddr, &iph->daddr, skb->dev->name, &gateway);
    }

    return NF_ACCEPT;
}

/* ------------------------------------------------------------------ */
/* Hook Callbacks                                                       */
/* ------------------------------------------------------------------ */

/*
 * Hook tại PRE_ROUTING: bắt Forwarded traffic (Client → Server → WAN → ...)
 * Đây là điểm TRƯỚC khi Kernel ra quyết định định tuyến.
 * Gán rtable đúng tại đây → Kernel sẽ Forward gói tin ra đúng WAN interface.
 */
static unsigned int mwan_hook_pre_routing(void *priv, struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
    return mwan_do_steer(skb, state->net);
}

/*
 * Hook tại LOCAL_OUT: bắt traffic phát sinh từ chính server (ping, iperf3 local...)
 * Forwarded traffic sẽ không đi qua đây.
 */
static unsigned int mwan_hook_local_out(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state)
{
    return mwan_do_steer(skb, state->net);
}

/* ------------------------------------------------------------------ */
/* Hook Registration                                                    */
/* ------------------------------------------------------------------ */

static struct nf_hook_ops mwan_nf_ops[] = {
    {
        .hook     = mwan_hook_pre_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_LAST, /* Sau tất cả nftables/iptables PRE_ROUTING rules */
    },
    {
        .hook     = mwan_hook_local_out,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_LAST, /* Sau tất cả nftables/iptables OUTPUT rules */
    },
};

int mwan_steer_init(void)
{
    int ret;
    pr_info("mwan_kmod: Registering PRE_ROUTING + LOCAL_OUT steering hooks\n");
    ret = nf_register_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
    if (ret < 0)
        pr_err("mwan_kmod: Failed to register hooks (err=%d)\n", ret);
    return ret;
}

void mwan_steer_cleanup(void)
{
    pr_info("mwan_kmod: Unregistering steering hooks\n");
    nf_unregister_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
}
