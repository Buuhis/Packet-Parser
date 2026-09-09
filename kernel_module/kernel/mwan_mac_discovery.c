#include "mwan_mac_discovery.h"
#include "mwan_state.h"

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

#define MWAN_MAC_DISCOVERY_ETHERTYPE 0x88B6
#define MWAN_MAC_DISCOVERY_MAGIC     0x4d574d44U /* "MWMD" */
#define MWAN_MAC_DISCOVERY_VERSION   2
#define MWAN_MAC_DISCOVERY_REQUEST   1
#define MWAN_MAC_DISCOVERY_RESPONSE  2
#define MWAN_MAC_RETRY_MS            1000
#define MWAN_MAC_REFRESH_MS          30000

struct mwan_mac_discovery_hdr {
    __be32 magic;
    u8 version;
    u8 type;
    __be16 reserved;
    __be32 node_id;
    __be32 tunnel_ip;
    __be64 nonce;
} __packed;

static void mwan_mac_discovery_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(mwan_mac_discovery_work,
                            mwan_mac_discovery_workfn);
static bool mwan_mac_discovery_running;

static struct mwan_tunnel *mwan_mac_find_tunnel(struct mwan_config *cfg,
                                                 int ifindex)
{
    u32 i;

    if (!cfg)
        return NULL;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex)
            return &cfg->tunnels[i];
    }
    return NULL;
}

static bool mwan_mac_is_resolved(struct mwan_tunnel *tun)
{
    bool resolved;

    spin_lock_bh(&tun->gateway_mac_lock);
    resolved = tun->mac_resolved &&
               is_valid_ether_addr(tun->gateway_mac) &&
               tun->peer_ip_resolved && tun->peer_tunnel_ip != 0;
    spin_unlock_bh(&tun->gateway_mac_lock);
    return resolved;
}

bool mwan_mac_get_peer(struct mwan_tunnel *tun, u8 mac[ETH_ALEN])
{
    bool resolved;

    if (unlikely(!tun || !mac))
        return false;

    spin_lock_bh(&tun->gateway_mac_lock);
    resolved = tun->mac_resolved &&
               is_valid_ether_addr(tun->gateway_mac);
    if (resolved)
        ether_addr_copy(mac, tun->gateway_mac);
    spin_unlock_bh(&tun->gateway_mac_lock);

    if (unlikely(!resolved))
        mwan_mac_discovery_kick();
    return resolved;
}

bool mwan_mac_get_peer_tunnel_ip(struct mwan_tunnel *tun,
                                 __be32 *peer_tunnel_ip)
{
    bool resolved;

    if (unlikely(!tun || !peer_tunnel_ip))
        return false;

    spin_lock_bh(&tun->gateway_mac_lock);
    resolved = tun->peer_ip_resolved && tun->peer_tunnel_ip != 0;
    if (resolved)
        *peer_tunnel_ip = tun->peer_tunnel_ip;
    spin_unlock_bh(&tun->gateway_mac_lock);

    if (unlikely(!resolved))
        mwan_mac_discovery_kick();
    return resolved;
}

static void mwan_mac_learn_peer(struct mwan_tunnel *tun, const u8 *mac,
                                __be32 peer_tunnel_ip)
{
    bool changed;

    if (!tun || !is_valid_ether_addr(mac) || peer_tunnel_ip == 0)
        return;

    spin_lock_bh(&tun->gateway_mac_lock);
    changed = !tun->mac_resolved || !tun->peer_ip_resolved ||
              !ether_addr_equal(tun->gateway_mac, mac) ||
              tun->peer_tunnel_ip != peer_tunnel_ip;
    ether_addr_copy(tun->gateway_mac, mac);
    tun->mac_resolved = true;
    tun->peer_tunnel_ip = peer_tunnel_ip;
    tun->peer_ip_resolved = true;
    spin_unlock_bh(&tun->gateway_mac_lock);

    if (changed)
        pr_info("mwan_kmod: learned peer MAC %pM and tunnel IP %pI4 on data tunnel %s\n",
                mac, &peer_tunnel_ip,
                tun->dev ? tun->dev->name : "unknown");
}

/* Caller holds rcu_read_lock(). A data tunnel is point-to-point and is
 * expected to have one IPv4 address used by the peer-discovery/BFD plane. */
static __be32 mwan_mac_local_ipv4(struct net_device *dev)
{
    struct in_device *in_dev;
    struct in_ifaddr *ifa;

    if (!dev)
        return 0;
    in_dev = __in_dev_get_rcu(dev);
    if (!in_dev)
        return 0;

    in_dev_for_each_ifa_rcu(ifa, in_dev) {
        if (ifa->ifa_local != 0)
            return ifa->ifa_local;
    }
    return 0;
}

static int mwan_mac_send(struct mwan_tunnel *tun, const u8 *dest,
                         u8 type, u32 node_id, u64 response_nonce,
                         gfp_t gfp)
{
    struct mwan_mac_discovery_hdr *hdr;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct net_device *dev;
    __be32 local_ip;
    u64 nonce;
    unsigned int headroom;
    int ret;

    if (!tun)
        return -EINVAL;
    dev = tun->dev;
    if (!dev || dev->type != ARPHRD_ETHER || !netif_running(dev))
        return -ENETDOWN;
    local_ip = mwan_mac_local_ipv4(dev);
    if (local_ip == 0)
        return -EADDRNOTAVAIL;

    nonce = response_nonce;
    if (type == MWAN_MAC_DISCOVERY_REQUEST) {
        do {
            nonce = get_random_u64();
        } while (nonce == 0);
        spin_lock_bh(&tun->gateway_mac_lock);
        tun->discovery_nonce = nonce;
        spin_unlock_bh(&tun->gateway_mac_lock);
    } else if (nonce == 0) {
        return -EINVAL;
    }

    headroom = LL_RESERVED_SPACE(dev);
    skb = alloc_skb(headroom + ETH_HLEN + sizeof(*hdr), gfp);
    if (!skb)
        return -ENOMEM;

    skb_reserve(skb, headroom);
    hdr = skb_put_zero(skb, sizeof(*hdr));
    hdr->magic = cpu_to_be32(MWAN_MAC_DISCOVERY_MAGIC);
    hdr->version = MWAN_MAC_DISCOVERY_VERSION;
    hdr->type = type;
    hdr->node_id = cpu_to_be32(node_id);
    hdr->tunnel_ip = local_ip;
    hdr->nonce = cpu_to_be64(nonce);

    eth = skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);
    ether_addr_copy(eth->h_dest, dest);
    ether_addr_copy(eth->h_source, dev->dev_addr);
    eth->h_proto = htons(MWAN_MAC_DISCOVERY_ETHERTYPE);

    skb->dev = dev;
    skb->protocol = eth->h_proto;
    skb_reset_network_header(skb);
    skb->ip_summed = CHECKSUM_NONE;
    ret = dev_queue_xmit(skb);
    return net_xmit_eval(ret) ? -EIO : 0;
}

static int mwan_mac_discovery_rx(struct sk_buff *skb, struct net_device *dev,
                                 struct packet_type *pt,
                                 struct net_device *orig_dev)
{
    struct mwan_mac_discovery_hdr hdr_buf;
    const struct mwan_mac_discovery_hdr *hdr;
    const struct ethhdr *eth;
    struct mwan_tunnel *tun;
    struct mwan_config *cfg;
    u64 nonce;
    bool nonce_matches = true;
    int ingress_ifindex;

    (void)pt;
    if (!skb)
        return NET_RX_DROP;

    ingress_ifindex = skb->dev ? skb->dev->ifindex :
                      (dev ? dev->ifindex :
                       (orig_dev ? orig_dev->ifindex : 0));
    eth = eth_hdr(skb);
    hdr = skb_header_pointer(skb, 0, sizeof(hdr_buf), &hdr_buf);
    if (!eth || !hdr ||
        be32_to_cpu(hdr->magic) != MWAN_MAC_DISCOVERY_MAGIC ||
        hdr->version != MWAN_MAC_DISCOVERY_VERSION ||
        (hdr->type != MWAN_MAC_DISCOVERY_REQUEST &&
         hdr->type != MWAN_MAC_DISCOVERY_RESPONSE) ||
        hdr->tunnel_ip == 0 || hdr->nonce == 0) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    tun = mwan_mac_find_tunnel(cfg, ingress_ifindex);
    if (!tun || !tun->is_ethernet) {
        pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-RX stage=UNKNOWN_TUNNEL ingress_ifindex=%d ethernet=%u\n",
                            ingress_ifindex,
                            tun && tun->is_ethernet ? 1 : 0);
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    nonce = be64_to_cpu(hdr->nonce);
    if (hdr->type == MWAN_MAC_DISCOVERY_RESPONSE) {
        spin_lock_bh(&tun->gateway_mac_lock);
        nonce_matches = tun->discovery_nonce == nonce;
        spin_unlock_bh(&tun->gateway_mac_lock);
    }
    if (!nonce_matches) {
        pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-RX stage=NONCE_MISMATCH tunnel=%s ingress_ifindex=%d received_nonce=%llu\n",
                            tun->dev ? tun->dev->name : "unknown",
                            ingress_ifindex,
                            (unsigned long long)nonce);
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    /* The ingress ifindex identifies the point-to-point data tunnel. The
     * source MAC comes from Ethernet; peer tunnel IP is explicitly carried
     * in the discovery payload and is never inferred from a subnet. */
    mwan_mac_learn_peer(tun, eth->h_source, hdr->tunnel_ip);
    if (hdr->type == MWAN_MAC_DISCOVERY_REQUEST) {
        int response_ret = mwan_mac_send(
            tun, eth->h_source, MWAN_MAC_DISCOVERY_RESPONSE,
            cfg->node_id, nonce, GFP_ATOMIC);

        if (response_ret)
            pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=RESPONSE_FAILED tunnel=%s ifindex=%d error=%d\n",
                                tun->dev ? tun->dev->name : "unknown",
                                tun->dev ? tun->dev->ifindex : 0,
                                response_ret);
        else
            pr_info_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=RESPONSE_SENT tunnel=%s ifindex=%d\n",
                                tun->dev ? tun->dev->name : "unknown",
                                tun->dev ? tun->dev->ifindex : 0);
    }
    rcu_read_unlock();

    kfree_skb(skb);
    return NET_RX_SUCCESS;
}

static struct packet_type mwan_mac_discovery_packet_type __read_mostly = {
    .type = cpu_to_be16(MWAN_MAC_DISCOVERY_ETHERTYPE),
    .func = mwan_mac_discovery_rx,
};

static void mwan_mac_discovery_workfn(struct work_struct *work)
{
    struct mwan_config *cfg;
    bool unresolved = false;
    u32 i;

    (void)work;
    if (!READ_ONCE(mwan_mac_discovery_running))
        return;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            struct mwan_tunnel *tun = &cfg->tunnels[i];
            bool tunnel_resolved;
            int send_ret;

            if (!tun->is_ethernet || !tun->dev)
                continue;
            tunnel_resolved = mwan_mac_is_resolved(tun);
            if (!tunnel_resolved)
                unresolved = true;
            send_ret = mwan_mac_send(tun, tun->dev->broadcast,
                                     MWAN_MAC_DISCOVERY_REQUEST,
                                     cfg->node_id, 0, GFP_ATOMIC);
            if (send_ret)
                pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=SEND_FAILED tunnel=%s ifindex=%d error=%d resolved=%u\n",
                                    tun->dev->name, tun->dev->ifindex,
                                    send_ret,
                                    mwan_mac_is_resolved(tun) ? 1 : 0);
            else if (!tunnel_resolved)
                pr_info_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=REQUEST_SENT tunnel=%s ifindex=%d\n",
                                    tun->dev->name, tun->dev->ifindex);
        }
    }
    rcu_read_unlock();

    if (READ_ONCE(mwan_mac_discovery_running))
        schedule_delayed_work(&mwan_mac_discovery_work,
                              msecs_to_jiffies(unresolved ?
                                              MWAN_MAC_RETRY_MS :
                                              MWAN_MAC_REFRESH_MS));
}

void mwan_mac_discovery_kick(void)
{
    if (READ_ONCE(mwan_mac_discovery_running))
        mod_delayed_work(system_wq, &mwan_mac_discovery_work, 0);
}

int mwan_mac_discovery_init(void)
{
    BUILD_BUG_ON(sizeof(struct mwan_mac_discovery_hdr) != 24);
    WRITE_ONCE(mwan_mac_discovery_running, true);
    dev_add_pack(&mwan_mac_discovery_packet_type);
    return 0;
}

void mwan_mac_discovery_cleanup(void)
{
    WRITE_ONCE(mwan_mac_discovery_running, false);
    cancel_delayed_work_sync(&mwan_mac_discovery_work);
    dev_remove_pack(&mwan_mac_discovery_packet_type);
}
