#include "mwan_mac_discovery.h"
#include "mwan_proto.h"
#include "mwan_state.h"
#include "mwan_steer.h"

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

#define MWAN_MAC_DISCOVERY_MAGIC     0x4d574d44U /* "MWMD" */
#define MWAN_MAC_DISCOVERY_VERSION   3
#define MWAN_MAC_DISCOVERY_REQUEST   1
#define MWAN_MAC_DISCOVERY_RESPONSE  2
#define MWAN_MAC_RETRY_MS            1000

struct mwan_mac_discovery_hdr {
    __be32 magic;
    u8 version;
    u8 type;
    __be16 reserved;
    __be32 node_id;
    __be32 tunnel_ip;
    __be64 nonce;
    u8 sender_mac[ETH_ALEN];
} __packed;

static void mwan_mac_discovery_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(mwan_mac_discovery_work,
                            mwan_mac_discovery_workfn);
static bool mwan_mac_discovery_running;

/* Pending registration identifies fail-closed data interfaces while the PQC
 * traffic key is absent.  It never sends discovery and is not visible to
 * crypto workers or active_paths. */
struct mwan_mac_pending_config {
    u32 node_id;
    u32 generation;
    u32 num_tunnels;
    struct mwan_tunnel tunnels[MAX_MWAN_TUNNELS];
};

static DEFINE_MUTEX(mwan_mac_pending_lock);
static struct mwan_mac_pending_config __rcu *mwan_mac_pending_cfg;

static struct mwan_tunnel *mwan_mac_find_tunnel(struct mwan_config *cfg,
                                                 int ifindex)
{
    u32 i;

    if (!cfg)
        return NULL;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex ||
            cfg->tunnels[i].configured_ifindex == ifindex)
            return &cfg->tunnels[i];
    }
    return NULL;
}

static struct mwan_tunnel *mwan_mac_find_pending_tunnel(
    struct mwan_mac_pending_config *cfg, int ifindex)
{
    u32 i;

    if (!cfg)
        return NULL;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex ||
            cfg->tunnels[i].configured_ifindex == ifindex)
            return &cfg->tunnels[i];
    }
    return NULL;
}

static struct net_device *mwan_mac_effective_dev(u32 configured_ifindex)
{
    struct net_device *configured_dev;
    struct net_device *upper_dev;
    struct net_device *macsec_dev = NULL;
    struct list_head *iter;

    configured_dev = dev_get_by_index(&init_net, configured_ifindex);
    if (!configured_dev)
        return NULL;

    rcu_read_lock();
    netdev_for_each_upper_dev_rcu(configured_dev, upper_dev, iter) {
        if (upper_dev->rtnl_link_ops && upper_dev->rtnl_link_ops->kind &&
            strcmp(upper_dev->rtnl_link_ops->kind, "macsec") == 0) {
            dev_hold(upper_dev);
            macsec_dev = upper_dev;
            break;
        }
    }
    rcu_read_unlock();

    if (!macsec_dev)
        return configured_dev;
    dev_put(configured_dev);
    return macsec_dev;
}

static void mwan_mac_pending_destroy(struct mwan_mac_pending_config *cfg)
{
    u32 i;

    if (!cfg)
        return;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].dev)
            dev_put(cfg->tunnels[i].dev);
    }
    kvfree(cfg);
}

static void mwan_mac_copy_peer_state(struct mwan_tunnel *dst,
                                     struct mwan_tunnel *src,
                                     bool copy_health)
{
    if (!dst || !src)
        return;

    spin_lock_bh(&src->gateway_mac_lock);
    if (src->mac_resolved && src->peer_ip_resolved &&
        is_valid_ether_addr(src->gateway_mac) &&
        src->peer_tunnel_ip != 0) {
        ether_addr_copy(dst->gateway_mac, src->gateway_mac);
        dst->mac_resolved = true;
        dst->peer_tunnel_ip = src->peer_tunnel_ip;
        dst->peer_ip_resolved = true;
        dst->discovery_nonce = src->discovery_nonce;
        dst->discovery_unresolved_reported =
            src->discovery_unresolved_reported;
    }
    spin_unlock_bh(&src->gateway_mac_lock);
    if (copy_health) {
        dst->published_up = READ_ONCE(src->published_up);
        dst->state_sequence = 0;
    }
}

int mwan_mac_discovery_configure_pending(u32 node_id, u32 generation,
                                         const u32 *ifindices,
                                         u32 num_tunnels)
{
    struct mwan_mac_pending_config *new_cfg;
    struct mwan_mac_pending_config *old_cfg;
    struct mwan_config *active_cfg;
    u32 i;
    u32 j;
    int ret = 0;

    if (!node_id ||
        !(generation & MWAN_DISCOVERY_GENERATION_FLAG) ||
        num_tunnels > MAX_MWAN_TUNNELS ||
        (num_tunnels && !ifindices))
        return -EINVAL;

    new_cfg = kvzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg)
        return -ENOMEM;
    new_cfg->node_id = node_id;
    new_cfg->generation = generation;
    new_cfg->num_tunnels = num_tunnels;

    for (i = 0; i < num_tunnels; i++) {
        struct mwan_tunnel *tun = &new_cfg->tunnels[i];

        if (!ifindices[i]) {
            ret = -EINVAL;
            goto err_destroy;
        }
        for (j = 0; j < i; j++) {
            if (ifindices[j] == ifindices[i]) {
                ret = -EEXIST;
                goto err_destroy;
            }
        }
        tun->configured_ifindex = ifindices[i];
        tun->dev = mwan_mac_effective_dev(ifindices[i]);
        if (!tun->dev) {
            ret = -ENODEV;
            goto err_destroy;
        }
        tun->ifindex = tun->dev->ifindex;
        tun->is_ethernet = tun->dev->type == ARPHRD_ETHER;
        spin_lock_init(&tun->gateway_mac_lock);
        if (!tun->is_ethernet) {
            ret = -EAFNOSUPPORT;
            goto err_destroy;
        }
    }

    /* Seed a pending reload from the active datapath without modifying it. */
    rcu_read_lock();
    active_cfg = rcu_dereference(g_mwan_cfg);
    if (active_cfg && active_cfg->node_id == node_id) {
        for (i = 0; i < new_cfg->num_tunnels; i++) {
            struct mwan_tunnel *active_tun = mwan_mac_find_tunnel(
                active_cfg, new_cfg->tunnels[i].configured_ifindex);

            if (active_tun)
                mwan_mac_copy_peer_state(&new_cfg->tunnels[i], active_tun,
                                         true);
        }
    }
    rcu_read_unlock();

    mutex_lock(&mwan_mac_pending_lock);
    old_cfg = rcu_dereference_protected(
        mwan_mac_pending_cfg,
        lockdep_is_held(&mwan_mac_pending_lock));
    if (old_cfg && old_cfg->node_id == node_id) {
        for (i = 0; i < new_cfg->num_tunnels; i++) {
            struct mwan_tunnel *old_tun = mwan_mac_find_pending_tunnel(
                old_cfg, new_cfg->tunnels[i].configured_ifindex);

            if (old_tun)
                mwan_mac_copy_peer_state(&new_cfg->tunnels[i], old_tun,
                                         true);
        }
    }
    rcu_assign_pointer(mwan_mac_pending_cfg, new_cfg);
    synchronize_rcu();
    mwan_mac_pending_destroy(old_cfg);
    mutex_unlock(&mwan_mac_pending_lock);

    pr_info("mwan_kmod: MAC-DISCOVERY-CONFIG state=PENDING node=%u generation=%u tunnels=%u datapath_active=0\n",
            node_id, generation, num_tunnels);
    return 0;

err_destroy:
    mwan_mac_pending_destroy(new_cfg);
    return ret;
}

void mwan_mac_discovery_import_pending(struct mwan_config *cfg)
{
    struct mwan_mac_pending_config *pending;
    u32 i;

    if (!cfg)
        return;

    mutex_lock(&mwan_mac_pending_lock);
    pending = rcu_dereference_protected(
        mwan_mac_pending_cfg,
        lockdep_is_held(&mwan_mac_pending_lock));
    if (!pending || pending->node_id != cfg->node_id)
        goto out;

    for (i = 0; i < cfg->num_tunnels; i++) {
        struct mwan_tunnel *src = mwan_mac_find_pending_tunnel(
            pending, cfg->tunnels[i].configured_ifindex);

        if (src)
            mwan_mac_copy_peer_state(&cfg->tunnels[i], src, true);
    }
out:
    mutex_unlock(&mwan_mac_pending_lock);
}

void mwan_mac_discovery_clear_pending(u32 node_id)
{
    struct mwan_mac_pending_config *old_cfg;

    mutex_lock(&mwan_mac_pending_lock);
    old_cfg = rcu_dereference_protected(
        mwan_mac_pending_cfg,
        lockdep_is_held(&mwan_mac_pending_lock));
    if (!old_cfg || (node_id && old_cfg->node_id != node_id)) {
        mutex_unlock(&mwan_mac_pending_lock);
        return;
    }
    RCU_INIT_POINTER(mwan_mac_pending_cfg, NULL);
    synchronize_rcu();
    mwan_mac_pending_destroy(old_cfg);
    mutex_unlock(&mwan_mac_pending_lock);
}

int mwan_mac_discovery_get_pending_peer(u32 ifindex,
                                        __be32 *peer_tunnel_ip)
{
    struct mwan_mac_pending_config *cfg;
    struct mwan_tunnel *tun;
    int ret = -ENOENT;

    if (!ifindex || !peer_tunnel_ip)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(mwan_mac_pending_cfg);
    tun = mwan_mac_find_pending_tunnel(cfg, ifindex);
    if (tun)
        ret = mwan_mac_get_peer_tunnel_ip(tun, peer_tunnel_ip) ?
              0 : -EAGAIN;
    rcu_read_unlock();
    return ret;
}

bool mwan_mac_discovery_is_pending_tunnel(u32 ifindex)
{
    struct mwan_mac_pending_config *cfg;
    bool found;

    if (!ifindex)
        return false;
    rcu_read_lock();
    cfg = rcu_dereference(mwan_mac_pending_cfg);
    found = mwan_mac_find_pending_tunnel(cfg, ifindex) != NULL;
    rcu_read_unlock();
    return found;
}

int mwan_mac_discovery_set_pending_state(u32 ifindex, u32 generation,
                                         u32 sequence, bool up)
{
    struct mwan_mac_pending_config *cfg;
    struct mwan_tunnel *tun;
    int ret = 0;

    if (!ifindex || !generation || !sequence)
        return -EINVAL;

    mutex_lock(&mwan_mac_pending_lock);
    cfg = rcu_dereference_protected(
        mwan_mac_pending_cfg,
        lockdep_is_held(&mwan_mac_pending_lock));
    if (!cfg) {
        ret = -ENOENT;
        goto out;
    }
    if (cfg->generation != generation) {
        ret = -ESTALE;
        goto out;
    }
    tun = mwan_mac_find_pending_tunnel(cfg, ifindex);
    if (!tun) {
        ret = -ENOENT;
        goto out;
    }
    if (sequence < tun->state_sequence ||
        (sequence == tun->state_sequence && tun->published_up != up)) {
        ret = -ESTALE;
        goto out;
    }
    tun->state_sequence = sequence;
    tun->published_up = up;
out:
    mutex_unlock(&mwan_mac_pending_lock);
    return ret;
}

int mwan_mac_discovery_get_pending_state(u32 ifindex, u32 *generation,
                                         u32 *sequence, bool *up)
{
    struct mwan_mac_pending_config *cfg;
    struct mwan_tunnel *tun;
    int ret = -ENOENT;

    if (!ifindex || !generation || !sequence || !up)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(mwan_mac_pending_cfg);
    tun = mwan_mac_find_pending_tunnel(cfg, ifindex);
    if (tun) {
        *generation = cfg->generation;
        *sequence = READ_ONCE(tun->state_sequence);
        *up = READ_ONCE(tun->published_up);
        ret = 0;
    }
    rcu_read_unlock();
    return ret;
}

int mwan_mac_discovery_rebind_pending(u32 node_id, u32 generation,
                                      u32 old_ifindex, u32 new_ifindex)
{
    struct mwan_mac_pending_config *cfg;
    u32 ifindices[MAX_MWAN_TUNNELS];
    u32 num_tunnels;
    u32 i;
    bool found = false;
    int ret = 0;

    if (!node_id || !generation || !old_ifindex || !new_ifindex)
        return -EINVAL;

    mutex_lock(&mwan_mac_pending_lock);
    cfg = rcu_dereference_protected(
        mwan_mac_pending_cfg,
        lockdep_is_held(&mwan_mac_pending_lock));
    if (!cfg) {
        ret = -ENOENT;
        goto out_unlock;
    }
    if (cfg->node_id != node_id || cfg->generation != generation) {
        ret = -ESTALE;
        goto out_unlock;
    }
    num_tunnels = cfg->num_tunnels;
    for (i = 0; i < num_tunnels; i++) {
        struct mwan_tunnel *tun = &cfg->tunnels[i];

        ifindices[i] = tun->configured_ifindex;
        if (tun->configured_ifindex == old_ifindex ||
            tun->ifindex == old_ifindex) {
            ifindices[i] = new_ifindex;
            found = true;
        }
    }
    if (!found)
        ret = -ENOENT;
out_unlock:
    mutex_unlock(&mwan_mac_pending_lock);
    if (ret)
        return ret;
    return mwan_mac_discovery_configure_pending(
        node_id, generation, ifindices, num_tunnels);
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

/* Return true once for each unresolved episode.  The flag is diagnostic only:
 * callers continue sending every discovery request on the normal schedule. */
static bool mwan_mac_report_unresolved_once(struct mwan_tunnel *tun)
{
    bool report = false;
    bool resolved;

    spin_lock_bh(&tun->gateway_mac_lock);
    resolved = tun->mac_resolved &&
               is_valid_ether_addr(tun->gateway_mac) &&
               tun->peer_ip_resolved && tun->peer_tunnel_ip != 0;
    if (!resolved && !tun->discovery_unresolved_reported) {
        tun->discovery_unresolved_reported = true;
        report = true;
    }
    spin_unlock_bh(&tun->gateway_mac_lock);
    return report;
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

static bool mwan_mac_learn_peer(struct mwan_tunnel *tun, const u8 *mac,
                                __be32 peer_tunnel_ip)
{
    bool changed;

    if (!tun || !is_valid_ether_addr(mac) || peer_tunnel_ip == 0)
        return false;

    spin_lock_bh(&tun->gateway_mac_lock);
    changed = !tun->mac_resolved || !tun->peer_ip_resolved ||
              !ether_addr_equal(tun->gateway_mac, mac) ||
              tun->peer_tunnel_ip != peer_tunnel_ip;
    ether_addr_copy(tun->gateway_mac, mac);
    tun->mac_resolved = true;
    tun->peer_tunnel_ip = peer_tunnel_ip;
    tun->peer_ip_resolved = true;
    tun->discovery_unresolved_reported = false;
    spin_unlock_bh(&tun->gateway_mac_lock);

    if (changed)
        pr_info("mwan_kmod: learned peer MAC %pM and tunnel IP %pI4 on data tunnel %s\n",
                mac, &peer_tunnel_ip,
                tun->dev ? tun->dev->name : "unknown");
    return changed;
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

static int mwan_mac_send(struct mwan_config *cfg, struct mwan_tunnel *tun,
                         const u8 *dest, u8 type, u32 node_id,
                         u64 response_nonce)
{
    struct mwan_mac_discovery_hdr hdr = { 0 };
    struct net_device *dev;
    __be32 local_ip;
    u64 nonce;

    if (!cfg || !tun)
        return -EINVAL;
    dev = tun->dev;
    if (!dev || dev->type != ARPHRD_ETHER || !netif_running(dev))
        return -ENETDOWN;
    rcu_read_lock();
    local_ip = mwan_mac_local_ipv4(dev);
    rcu_read_unlock();
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

    hdr.magic = cpu_to_be32(MWAN_MAC_DISCOVERY_MAGIC);
    hdr.version = MWAN_MAC_DISCOVERY_VERSION;
    hdr.type = type;
    hdr.node_id = cpu_to_be32(node_id);
    hdr.tunnel_ip = local_ip;
    hdr.nonce = cpu_to_be64(nonce);
    ether_addr_copy(hdr.sender_mac, dev->dev_addr);

    return mwan_l2_pqc_encrypt_control_xmit(cfg, tun, dest, &hdr,
                                             sizeof(hdr));
}

int mwan_mac_discovery_receive_encrypted(struct mwan_config *cfg,
                                         struct sk_buff *skb)
{
    struct mwan_mac_discovery_hdr hdr_buf;
    const struct mwan_mac_discovery_hdr *hdr;
    struct mwan_tunnel *tun;
    u64 nonce;
    bool nonce_matches = true;
    bool peer_changed;
    int ingress_ifindex;

    if (!cfg || !skb)
        return -EINVAL;

    ingress_ifindex = skb->dev ? skb->dev->ifindex : 0;
    hdr = skb_header_pointer(skb, 0, sizeof(hdr_buf), &hdr_buf);
    if (!hdr ||
        be32_to_cpu(hdr->magic) != MWAN_MAC_DISCOVERY_MAGIC ||
        hdr->version != MWAN_MAC_DISCOVERY_VERSION ||
        (hdr->type != MWAN_MAC_DISCOVERY_REQUEST &&
         hdr->type != MWAN_MAC_DISCOVERY_RESPONSE) ||
        hdr->tunnel_ip == 0 || hdr->nonce == 0 ||
        !is_valid_ether_addr(hdr->sender_mac)) {
        return -EBADMSG;
    }

    tun = mwan_mac_find_tunnel(cfg, ingress_ifindex);
    if (!tun || !tun->is_ethernet) {
        pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-RX stage=UNKNOWN_TUNNEL ingress_ifindex=%d ethernet=%u active_config=1 encrypted=1\n",
                            ingress_ifindex,
                            tun && tun->is_ethernet ? 1 : 0);
        return -ENODEV;
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
        return -ESTALE;
    }

    /* The ingress ifindex identifies the point-to-point data tunnel.  Peer
     * MAC and tunnel IP both come from the authenticated payload; neither is
     * trusted from the mutable outer Ethernet header or inferred by subnet. */
    peer_changed = mwan_mac_learn_peer(tun, hdr->sender_mac,
                                       hdr->tunnel_ip);
    if (hdr->type == MWAN_MAC_DISCOVERY_REQUEST) {
        int response_ret = mwan_mac_send(
            cfg, tun, hdr->sender_mac, MWAN_MAC_DISCOVERY_RESPONSE,
            cfg->node_id, nonce);

        if (response_ret)
            pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=RESPONSE_FAILED tunnel=%s ifindex=%d error=%d\n",
                                tun->dev ? tun->dev->name : "unknown",
                                tun->dev ? tun->dev->ifindex : 0,
                                response_ret);
        else if (peer_changed)
            pr_info("mwan_kmod: MAC-DISCOVERY-TX stage=RESPONSE_SENT tunnel=%s ifindex=%d peer_state=CHANGED encrypted=1\n",
                    tun->dev ? tun->dev->name : "unknown",
                    tun->dev ? tun->dev->ifindex : 0);
    }
    return 0;
}

static void mwan_mac_discovery_workfn(struct work_struct *work)
{
    struct mwan_config *cfg;
    bool unresolved = false;
    u32 i;

    (void)work;
    if (!READ_ONCE(mwan_mac_discovery_running))
        return;

    /* Encryption can sleep, so keep the active config stable with the update
     * mutex rather than holding an RCU read lock across crypto.  Pending
     * profiles have no traffic key and deliberately send nothing. */
    mutex_lock(&mwan_cfg_update_lock);
    cfg = rcu_dereference_protected(
        g_mwan_cfg, lockdep_is_held(&mwan_cfg_update_lock));
    if (cfg && cfg->num_tunnels && cfg->encrypt_on &&
        cfg->encrypt_layer == 2 &&
        cfg->encrypt_type == MWAN_CRYPT_PQC_GCM && cfg->key_id) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            struct mwan_tunnel *tun = &cfg->tunnels[i];
            bool tunnel_resolved;
            int send_ret;

            if (!tun->is_ethernet || !tun->dev)
                continue;
            tunnel_resolved = mwan_mac_is_resolved(tun);
            if (tunnel_resolved)
                continue;
            unresolved = true;
            send_ret = mwan_mac_send(cfg, tun, tun->dev->broadcast,
                                     MWAN_MAC_DISCOVERY_REQUEST,
                                     cfg->node_id, 0);
            if (send_ret)
                pr_warn_ratelimited("mwan_kmod: MAC-DISCOVERY-TX stage=SEND_FAILED tunnel=%s ifindex=%d error=%d resolved=%u\n",
                                    tun->dev->name, tun->dev->ifindex,
                                    send_ret,
                                    mwan_mac_is_resolved(tun) ? 1 : 0);
            else if (!tunnel_resolved &&
                     mwan_mac_report_unresolved_once(tun))
                pr_info("mwan_kmod: MAC-DISCOVERY-TX stage=REQUEST_SENT tunnel=%s ifindex=%d peer_state=UNRESOLVED\n",
                        tun->dev->name, tun->dev->ifindex);
        }
    }
    mutex_unlock(&mwan_cfg_update_lock);

    if (READ_ONCE(mwan_mac_discovery_running) && unresolved)
        schedule_delayed_work(&mwan_mac_discovery_work,
                              msecs_to_jiffies(MWAN_MAC_RETRY_MS));
}

void mwan_mac_discovery_kick(void)
{
    if (READ_ONCE(mwan_mac_discovery_running))
        mod_delayed_work(system_wq, &mwan_mac_discovery_work, 0);
}

int mwan_mac_discovery_init(void)
{
    BUILD_BUG_ON(sizeof(struct mwan_mac_discovery_hdr) != 30);
    WRITE_ONCE(mwan_mac_discovery_running, true);
    return 0;
}

void mwan_mac_discovery_cleanup(void)
{
    WRITE_ONCE(mwan_mac_discovery_running, false);
    cancel_delayed_work_sync(&mwan_mac_discovery_work);
    mwan_mac_discovery_clear_pending(0);
}
