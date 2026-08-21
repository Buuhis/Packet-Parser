#include "mwan_mac_discovery.h"
#include "mwan_state.h"

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/jiffies.h>
#include <linux/inetdevice.h>
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
    resolved = tun->mac_resolved && tun->peer_ip_resolved &&
               is_valid_ether_addr(tun->gateway_mac) &&
               tun->peer_tunnel_ip != 0;
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

static __be32 mwan_mac_local_ip(const struct mwan_tunnel *tun)
{
    if (!tun || !tun->dev)
        return 0;
    if (tun->local_tunnel_ip)
        return tun->local_tunnel_ip;
    return inet_select_addr(tun->dev, 0, RT_SCOPE_LINK);
}

static void mwan_mac_learn_peer(struct mwan_tunnel *tun, const u8 *mac,
                                __be32 peer_ip, u64 nonce)
{
    bool changed;
    __be32 local_ip;

    if (!tun || !is_valid_ether_addr(mac) || !peer_ip)
        return;
    local_ip = mwan_mac_local_ip(tun);
    if (!local_ip || peer_ip == local_ip || peer_ip == htonl(INADDR_BROADCAST))
        return;

    spin_lock_bh(&tun->gateway_mac_lock);
    if (!nonce || nonce != tun->discovery_nonce) {
        spin_unlock_bh(&tun->gateway_mac_lock);
        return;
    }
    changed = !tun->mac_resolved || !tun->peer_ip_resolved ||
              !ether_addr_equal(tun->gateway_mac, mac) ||
              tun->peer_tunnel_ip != peer_ip;
    ether_addr_copy(tun->gateway_mac, mac);
    tun->mac_resolved = true;
    tun->peer_tunnel_ip = peer_ip;
    tun->peer_ip_resolved = true;
    if (changed && ++tun->peer_generation == 0)
        tun->peer_generation = 1;
    spin_unlock_bh(&tun->gateway_mac_lock);

    if (changed)
        pr_info("mwan_kmod: learned peer tuple mac=%pM ip=%pI4 on data tunnel %s\n",
                mac, &peer_ip, tun->dev ? tun->dev->name : "unknown");
}

static int mwan_mac_send(struct mwan_tunnel *tun, const u8 *dest,
                         u8 type, u32 node_id, u64 nonce, gfp_t gfp)
{
    struct mwan_mac_discovery_hdr *hdr;
    struct sk_buff *skb;
    struct ethhdr *eth;
    unsigned int headroom;
    int ret;
    struct net_device *dev;
    __be32 local_ip;

    if (!tun)
        return -EINVAL;
    dev = tun->dev;
    if (!dev || dev->type != ARPHRD_ETHER || !netif_running(dev))
        return -ENETDOWN;
    local_ip = mwan_mac_local_ip(tun);
    if (!local_ip)
        return -EADDRNOTAVAIL;

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
         hdr->type != MWAN_MAC_DISCOVERY_RESPONSE)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    tun = mwan_mac_find_tunnel(cfg, ingress_ifindex);
    if (!tun || !tun->is_ethernet) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    if (be32_to_cpu(hdr->node_id) == cfg->node_id ||
        ether_addr_equal(eth->h_source, tun->dev->dev_addr)) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    /* A request is answered but never trusted as discovery completion. Both
     * sites issue their own nonce-bearing request, so learning is symmetric
     * and a stale/unsolicited response cannot replace the tuple. */
    if (hdr->type == MWAN_MAC_DISCOVERY_RESPONSE)
        mwan_mac_learn_peer(tun, eth->h_source, hdr->tunnel_ip,
                            be64_to_cpu(hdr->nonce));
    else
        mwan_mac_send(tun, eth->h_source,
                      MWAN_MAC_DISCOVERY_RESPONSE, cfg->node_id,
                      be64_to_cpu(hdr->nonce),
                      GFP_ATOMIC);
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
            u64 nonce;

            if (!tun->is_ethernet || !tun->dev)
                continue;
            if (!mwan_mac_is_resolved(tun))
                unresolved = true;
            nonce = get_random_u64();
            if (!nonce)
                nonce = 1;
            spin_lock_bh(&tun->gateway_mac_lock);
            tun->discovery_nonce = nonce;
            spin_unlock_bh(&tun->gateway_mac_lock);
            mwan_mac_send(tun, tun->dev->broadcast,
                          MWAN_MAC_DISCOVERY_REQUEST, cfg->node_id, nonce,
                          GFP_ATOMIC);
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
