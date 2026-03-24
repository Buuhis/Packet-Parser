#include "mwan_steer.h"
#include "mwan_state.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <net/route.h>

/*
 * mwan_hook_post_routing - Core TX steering hook
 *
 * Chạy SAU firewall (NF_IP_PRI_LAST). Khi gói tin được firewall cho phép:
 *  1. Kiểm tra Destination IP có thuộc Overlay CIDR không
 *  2. Hash 5-tuple để chọn tunnel (đảm bảo flow affinity)
 *  3. Tra ARP cache lấy MAC của gateway trên tunnel đích
 *  4. Tự xây dựng Ethernet Header với MAC chính xác
 *  5. Gọi dev_queue_xmit() và trả về NF_STOLEN
 *     → Kernel sẽ KHÔNG gọi ip_finish_output2() nên sẽ không ghi MAC sai
 */
static unsigned int mwan_hook_post_routing(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    int target_ifindex = 0;
    __be32 gateway = 0;

    if (!skb)
        return NF_ACCEPT;

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

    /* 2. Hash: 5-tuple để đảm bảo cùng flow → cùng tunnel */
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

    /* 3. Steer: Chọn tunnel theo hash + weight */
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
                    gateway = cfg->tunnels[i].gateway;
                    break;
                }
            }
        }
    }
    rcu_read_unlock();

    if (target_ifindex == 0 || gateway == 0) {
        pr_warn_ratelimited("mwan_kmod: No valid tunnel/gateway found, passing through\n");
        return NF_ACCEPT;
    }

    /* 4. Lấy target net_device */
    struct net_device *target_dev = dev_get_by_index(state->net, target_ifindex);
    if (!target_dev) {
        pr_warn_ratelimited("mwan_kmod: Target ifindex %u not found\n", target_ifindex);
        return NF_ACCEPT;
    }

    /* 5. Kiểm tra MTU - nếu quá lớn thì drop để tránh corruption */
    if (skb->len > target_dev->mtu + ETH_HLEN) {
        pr_warn_ratelimited("mwan_kmod: Packet too large (%u) for %s (mtu=%u), dropping\n",
                            skb->len, target_dev->name, target_dev->mtu);
        dev_put(target_dev);
        return NF_DROP;
    }

    /*
     * 6. Tra ARP cache lấy MAC của gateway trên target interface
     *
     * neigh_lookup() chỉ tìm trong cache, không gửi ARP request.
     * Trường hợp chưa có trong cache:
     *   - Gửi ARP request thủ công (arp_send)
     *   - Drop gói tin hiện tại (gói ping tiếp theo sẽ thành công sau khi ARP reply)
     */
    struct neighbour *neigh = neigh_lookup(&arp_tbl, &gateway, target_dev);
    if (!neigh || !(neigh->nud_state & NUD_VALID)) {
        /* Trigger ARP resolution nếu chưa có */
        arp_send(ARPOP_REQUEST, ETH_P_ARP, gateway,
                 target_dev, 0, NULL,
                 target_dev->dev_addr, NULL);

        pr_debug("mwan_kmod: ARP pending for %pI4 on %s, dropping packet\n",
                 &gateway, target_dev->name);

        if (neigh)
            neigh_release(neigh);
        dev_put(target_dev);
        return NF_DROP;
    }

    /*
     * 7. Tự xây dựng Ethernet Header (đây là bước then chốt)
     *
     * Tại POST_ROUTING, gói tin đang ở dạng L3 (IP header là đầu tiên).
     * Ta cần skb_push để mở rộng buffer phía trước và viết Ethernet header vào đó.
     */
    if (skb_cow_head(skb, ETH_HLEN + target_dev->needed_headroom)) {
        pr_warn_ratelimited("mwan_kmod: Failed to cow skb head\n");
        neigh_release(neigh);
        dev_put(target_dev);
        return NF_DROP;
    }

    skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);

    struct ethhdr *eth = eth_hdr(skb);
    /* Destination MAC = MAC của gateway trên interface mục tiêu (lấy từ ARP cache) */
    memcpy(eth->h_dest, neigh->ha, ETH_ALEN);
    /* Source MAC = MAC của interface mục tiêu của chúng ta */
    memcpy(eth->h_source, target_dev->dev_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    neigh_release(neigh);

    /* 8. Gán interface và metadata */
    skb->dev      = target_dev;
    skb->protocol = htons(ETH_P_IP);
    skb_clear_hash(skb);

    /* Tách skb khỏi socket gốc để tránh accounting sai lầm */
    skb_orphan(skb);

    pr_debug("mwan_kmod: Steered %pI4 -> %pI4 via %s, dst_mac=%pM\n",
             &iph->saddr, &iph->daddr, target_dev->name, eth->h_dest);

    /* 9. Đẩy thẳng xuống driver, bypass ip_finish_output2() */
    dev_queue_xmit(skb);
    dev_put(target_dev);

    /* 10. NF_STOLEN: Báo Kernel "ta đã xử lý rồi, đừng đụng vào nữa" */
    return NF_STOLEN;
}

/* Netfilter Hook Definition */
static struct nf_hook_ops mwan_nf_ops = {
    .hook     = mwan_hook_post_routing,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST, /* Chạy sau tất cả firewall rules */
};

/* Hook Registration */
int mwan_steer_init(void) {
    pr_info("mwan_kmod: Registering POST_ROUTING steering hook (NF_STOLEN mode)\n");
    return nf_register_net_hook(&init_net, &mwan_nf_ops);
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hook\n");
    nf_unregister_net_hook(&init_net, &mwan_nf_ops);
}
