#include "mwan_steer.h"
#include "mwan_state.h"
#include "mwan_proto.h"
#include "mwan_mac_discovery.h"
#include "mwan_multicore.h"

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/if_ether.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

extern struct net init_net;

static struct mwan_tunnel *find_mwan_tunnel(struct mwan_config *cfg, u32 ifindex)
{
    int i;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (cfg->tunnels[i].ifindex == ifindex)
            return &cfg->tunnels[i];
    }
    return NULL;
}

static bool is_mwan_tunnel(struct mwan_config *cfg, u32 ifindex)
{
    return find_mwan_tunnel(cfg, ifindex) != NULL;
}

static const char *mwan_ct_info_name(struct nf_conn *ct,
                                     enum ip_conntrack_info ctinfo)
{
    if (!ct)
        return "NONE";

    switch (ctinfo) {
    case IP_CT_ESTABLISHED:
        return "ESTABLISHED";
    case IP_CT_RELATED:
        return "RELATED";
    case IP_CT_NEW:
        return "NEW";
    case IP_CT_ESTABLISHED_REPLY:
        return "ESTABLISHED_REPLY";
    case IP_CT_RELATED_REPLY:
        return "RELATED_REPLY";
    case IP_CT_UNTRACKED:
        return "UNTRACKED";
    default:
        return "UNKNOWN";
    }
}

/* Read-only diagnostic: this must never change skb, conntrack or verdict. */
static void mwan_fw_diag_log(const char *stage, struct sk_buff *skb,
                             const struct nf_hook_state *state,
                             int encap_type, const char *action,
                             const char *selected_dev)
{
    enum ip_conntrack_info ctinfo = IP_CT_UNTRACKED;
    struct iphdr iph_buf;
    const struct iphdr *iph;
    struct nf_conn *ct;

    if (!READ_ONCE(mwan_fw_diag_enabled) || !skb)
        return;

    iph = skb_header_pointer(skb, skb_network_offset(skb),
                             sizeof(iph_buf), &iph_buf);
    if (!iph || iph->version != 4)
        return;

    ct = nf_ct_get(skb, &ctinfo);
    pr_info_ratelimited("mwan_kmod: FWDIAG stage=%s in=%s out=%s iif=%d "
                        "src=%pI4 dst=%pI4 proto=%u len=%u "
                        "ct=%s/%d tracked=%u confirmed=%u encap=%d "
                        "action=%s selected=%s\n",
                        stage,
                        state && state->in ? state->in->name : "-",
                        state && state->out ? state->out->name : "-",
                        skb->skb_iif, &iph->saddr, &iph->daddr,
                        iph->protocol, skb->len,
                        mwan_ct_info_name(ct, ctinfo),
                        ct ? (int)ctinfo : -1, !!ct,
                        ct ? !!nf_ct_is_confirmed(ct) : 0,
                        encap_type, action ? action : "-",
                        selected_dev ? selected_dev : "-");
}

/* Helper function to check if packet is PQC handshake traffic (UDP port 7090) */
static inline bool is_pqc_handshake_packet(struct sk_buff *skb, struct iphdr *iph)
{
    struct udphdr udph_buf;
    const struct udphdr *udph;
    int network_offset;
    int ip_hlen;

    if (!skb || !iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_UDP)
        return false;
    /* A non-initial IPv4 fragment does not carry the UDP ports.  Locally
     * generated UDP is seen here before ip_finish_output() fragments it. */
    if (iph->frag_off & htons(IP_OFFSET))
        return false;

    network_offset = skb_network_offset(skb);
    ip_hlen = iph->ihl * 4;
    if (network_offset < 0 || ntohs(iph->tot_len) <
                              ip_hlen + sizeof(struct udphdr))
        return false;
    udph = skb_header_pointer(skb, network_offset + ip_hlen,
                              sizeof(udph_buf), &udph_buf);
    if (!udph)
        return false;

    return udph->dest == htons(7090) || udph->source == htons(7090);
}

/* Single-hop BFD probes belong to the tunnel selected by their bound
 * userspace socket.  They must not be re-hashed onto another data tunnel. */
static inline bool is_bfd_control_packet(struct sk_buff *skb,
                                         struct iphdr *iph)
{
    struct udphdr udph_buf;
    const struct udphdr *udph;
    int network_offset;
    int ip_hlen;

    if (!skb || !iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_UDP ||
        (iph->frag_off & htons(IP_OFFSET)) != 0)
        return false;
    network_offset = skb_network_offset(skb);
    ip_hlen = iph->ihl * 4;
    if (network_offset < 0 || ntohs(iph->tot_len) <
                              ip_hlen + sizeof(struct udphdr))
        return false;
    udph = skb_header_pointer(skb, network_offset + ip_hlen,
                              sizeof(udph_buf), &udph_buf);
    return udph && udph->dest == htons(3784);
}

static unsigned int mwan_dispatch_encap(struct sk_buff *skb,
                                        struct mwan_config *cfg,
                                        u8 tun_idx,
                                        const struct mwan_tx_flow_context *tx_ctx)
{
    struct mwan_tunnel *tun = &cfg->tunnels[tun_idx];

    switch (tun->encap_type) {
    case MWAN_ENCAP_NONE:
        return mwan_handle_encap_none(skb, cfg, tun_idx, tx_ctx);
    case MWAN_ENCAP_MACSEC:
        return mwan_handle_encap_macsec(skb, tun);
    case MWAN_ENCAP_L3_CUSTOM:
        return mwan_handle_encap_l3(skb, tun);
    case MWAN_ENCAP_L3_PQC:
        return mwan_handle_encap_l3_pqc(skb, tun);
    case MWAN_ENCAP_L2_PQC:
        return mwan_handle_encap_l2_pqc(skb, cfg, tun_idx, tx_ctx);
    default:
        return mwan_handle_encap_none(skb, cfg, tun_idx, tx_ctx);
    }
}

/* The core TX steering logic */
static unsigned int mwan_hook_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;
    u32 hash = 0;
    
    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // pr_info_ratelimited("mwan_kmod: POST_ROUTING hit: dest %pI4, out_dev: %s (ifindex: %d)\n",
    //                     &iph->daddr, state->out ? state->out->name : "NULL",
    //                     state->out ? state->out->ifindex : -1);

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    
    if (!cfg || cfg->num_tunnels == 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Filter: Check if Outbound Interface is managed by MWAN */
    if (!state->out || !is_mwan_tunnel(cfg, state->out->ifindex)) {
        /* A packet received from a managed tunnel and routed to LAN must be
         * left untouched.  This log proves that POST_ROUTING did so. */
        if (is_mwan_tunnel(cfg, skb->skb_iif))
            mwan_fw_diag_log("TX_POST_PASS", skb, state, -1,
                             "ACCEPT_UNMANAGED_OUT", NULL);
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Preserve BFD path identity: use the tunnel chosen by routing and the
     * bound socket, while retaining the normal conntrack + encap pipeline.
     * This observes liveness only; it does not alter the weighted data LUT. */
    if (is_bfd_control_packet(skb, iph)) {
        struct mwan_tunnel *tun = find_mwan_tunnel(cfg,
                                                   state->out->ifindex);
        u8 tun_idx;
        int confirm_ret;
        unsigned int ret;

        if (!tun) {
            rcu_read_unlock();
            return NF_DROP;
        }
        tun_idx = (u8)(tun - cfg->tunnels);
        confirm_ret = nf_conntrack_confirm(skb);
        if (unlikely(confirm_ret != NF_ACCEPT)) {
            rcu_read_unlock();
            return (unsigned int)confirm_ret;
        }
        ret = mwan_dispatch_encap(skb, cfg, tun_idx, NULL);
        rcu_read_unlock();
        return ret;
    }

    /* Bypass PQC handshake traffic (UDP port 7090) */
    if (is_pqc_handshake_packet(skb, iph)) {
        /* Keep control traffic on the route/interface selected by the
         * normal IPv4 stack.  In particular, do not steal the skb and call
         * dev_queue_xmit() here: doing that bypasses the remaining output
         * path, including its normal MTU/fragmentation handling. */
        mwan_fw_diag_log("TX_POST", skb, state, -1,
                         "ACCEPT_PQC_HANDSHAKE", state->out->name);
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    // pr_info_ratelimited("mwan_kmod: MATCHED managed tunnel: %s (ifindex: %d). Steering flow...\n",
    //                     state->out->name, state->out->ifindex);

    /* Steer & Encrypt all matched tunnel traffic */

    /* 2. Hash: Use kernel-cached/hardware RSS hash, but fallback to custom L3-only hash for IP fragments */
    if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
        hash = (__force u32)iph->saddr ^ (__force u32)iph->daddr;
    } else {
        hash = skb_get_hash(skb);
    }
    
    /* 3. Steer only across BFD-published UP tunnels.  The view is immutable
     * for the lifetime of this RCU read-side critical section. */
    {
        const struct mwan_active_paths *active =
            rcu_dereference(cfg->active_paths);
        struct mwan_tunnel *tun;
        struct mwan_tx_flow_context tx_ctx = { 0 };
        const struct mwan_tx_flow_context *dispatch_ctx = NULL;
        unsigned int ret = NF_ACCEPT;
        int confirm_ret;
        int select_ret;
        u16 selected_tun_idx;
        u8 tun_idx;

        if (!active || active->active_count == 0 ||
            active->total_weight == 0) {
            mwan_state_count_no_active_drop();
            rcu_read_unlock();
            return NF_DROP;
        }

        /* Keep the weighted active LUT as the fallback and as the stable
         * final tie-breaker used by the flow-aware selector. */
        tun_idx = active->tunnel_idx_lut[hash & (MWAN_LUT_SIZE - 1)];
        if (unlikely(tun_idx >= cfg->num_tunnels)) {
            rcu_read_unlock();
            return NF_DROP;
        }
        tun = &cfg->tunnels[tun_idx];

        /* Every asynchronous encap handler below takes ownership of skb and
         * normally returns NF_STOLEN.  Confirm a NEW conntrack entry first,
         * otherwise a later conntrack-confirm hook will never see this skb
         * and the reply can be classified as INVALID by nftables.  This is a
         * no-op for untracked packets and already-confirmed connections. */
        confirm_ret = nf_conntrack_confirm(skb);
        if (unlikely(confirm_ret != NF_ACCEPT)) {
            mwan_fw_diag_log("TX_POST", skb, state, tun->encap_type,
                             "CONNTRACK_CONFIRM_REJECT",
                             tun->dev ? tun->dev->name : NULL);
            pr_warn_ratelimited("mwan_kmod: conntrack confirm rejected TX packet ret=%d\n",
                                confirm_ret);
            rcu_read_unlock();
            return (unsigned int)confirm_ret;
        }

        /* Only the two established asynchronous datapaths participate in
         * stateful least-load selection. BFD and PQC handshake traffic have
         * already returned through their dedicated branches above; other
         * encryption modes retain their existing weighted-LUT behaviour. */
        if (tun->encap_type == MWAN_ENCAP_NONE ||
            tun->encap_type == MWAN_ENCAP_L2_PQC) {
            hash = mwan_multicore_flow_info(skb, &tx_ctx.info);
            tx_ctx.packet_class = mwan_multicore_packet_classify(skb);
            select_ret = mwan_l2_tx_flow_select_tunnel(
                cfg, &tx_ctx.info.key, hash,
                tx_ctx.packet_class == MWAN_PACKET_CONTROL,
                &selected_tun_idx, &tx_ctx.flow);
            if (unlikely(select_ret)) {
                rcu_read_unlock();
                return NF_DROP;
            }
            if (unlikely(selected_tun_idx >= cfg->num_tunnels)) {
                mwan_l2_tx_flow_put(tx_ctx.flow);
                rcu_read_unlock();
                return NF_DROP;
            }
            tun_idx = (u8)selected_tun_idx;
            tun = &cfg->tunnels[tun_idx];
            dispatch_ctx = &tx_ctx;
        }

        mwan_fw_diag_log("TX_POST", skb, state, tun->encap_type,
                         "DISPATCH", tun->dev ? tun->dev->name : NULL);

        ret = mwan_dispatch_encap(skb, cfg, tun_idx, dispatch_ctx);
        mwan_l2_tx_flow_put(tx_ctx.flow);
        
        rcu_read_unlock();
        return ret;
    }
}

/* The core Inbound processing logic */
static unsigned int mwan_hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct mwan_config *cfg;

    if (!skb) return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // if (skb->dev && (strncmp(skb->dev->name, "ne_", 3) == 0 ||
    //                  strncmp(skb->dev->name, "l2tun", 5) == 0 ||
    //                  strncmp(skb->dev->name, "enp", 3) == 0 ||
    //                  strncmp(skb->dev->name, "eno", 3) == 0)) {
    //     static int rx_debug_count = 0;
    //     if (rx_debug_count < 100) {
    //         rx_debug_count++;
    //         pr_info("mwan_kmod: [RX debug %d] dev %s, proto %d, len %d, saddr %pI4, daddr %pI4\n",
    //                 rx_debug_count, skb->dev->name, iph->protocol, skb->len, &iph->saddr, &iph->daddr);
    //     }
    // }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);

    if (!cfg) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* 1. Check if packet is coming from one of our WAN tunnels */
    struct mwan_tunnel *tun = find_mwan_tunnel(cfg, skb->dev->ifindex);
    if (tun) {
        mwan_fw_diag_log("RX_PRE", skb, state, tun->encap_type,
                         tun->encap_type == MWAN_ENCAP_L2_PQC ?
                         "L2_PLAINTEXT_REINJECT" : "ENTER_TUNNEL",
                         tun->dev ? tun->dev->name : NULL);
        /* If this tunnel is configured for L2 PQC encapsulation,
         * we bypass L3 decryption completely because the packet
         * was already decrypted at the L2 layer handler. */
        if (tun->encap_type == MWAN_ENCAP_L2_PQC) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }

        /* Bypass decryption for PQC handshake packets */
        if (is_pqc_handshake_packet(skb, iph)) {
            rcu_read_unlock();
            return NF_ACCEPT;
        }
        // pr_info_ratelimited("mwan_kmod: PRE_ROUTING hit from tunnel %s, proto %d, saddr %pI4, daddr %pI4\n",
        //                     skb->dev->name, iph->protocol, &iph->saddr, &iph->daddr);
        
        /* 2. Decrypt if encryption is enabled */
        if (cfg->encrypt_on && cfg->tfm) {
            int dec_ret;
            if (cfg->encrypt_type == MWAN_CRYPT_PQC_GCM) {
                /* L3-PQC: cfg->tfm holds PQC session key */
                dec_ret = (int)mwan_handle_decap_l3_pqc(skb, NULL);
            } else {
                /* L3-Custom: cfg->tfm holds static AES-GCM key */
                dec_ret = mwan_handle_decap_l3(skb, cfg);
            }
            if (dec_ret != MWAN_DECAP_CONTINUE) {
                pr_info_ratelimited("mwan_kmod: PRE_ROUTING decryption failed/drop with ret %d\n", dec_ret);
                rcu_read_unlock();
                return (unsigned int)dec_ret;
            }
        }
    }

    rcu_read_unlock();
    return NF_ACCEPT;
}

/* Runs after IPv4 conntrack (-200), immediately before a normal nftables
 * filter-priority (0) FORWARD chain.  It is diagnostic-only and always
 * returns NF_ACCEPT, so nftables remains solely responsible for filtering. */
static unsigned int mwan_hook_forward_diag(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
    struct mwan_config *cfg;

    if (!READ_ONCE(mwan_fw_diag_enabled) || !skb)
        return NF_ACCEPT;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && ((state->in && is_mwan_tunnel(cfg, state->in->ifindex)) ||
                (state->out && is_mwan_tunnel(cfg, state->out->ifindex))))
        mwan_fw_diag_log("FWD_PRE_NFT", skb, state, -1,
                         "OBSERVE_ONLY", NULL);
    rcu_read_unlock();

    return NF_ACCEPT;
}

/* Netfilter Hook Definitions */
static struct nf_hook_ops mwan_nf_ops[] = {
    {
        .hook     = mwan_hook_post_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_LAST, 
    },
    {
        .hook     = mwan_hook_pre_routing,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST, 
    },
    {
        .hook     = mwan_hook_forward_diag,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FILTER - 1,
    },
};

/* Hook Registration */
int mwan_steer_init(void) {
    int err;
    pr_info("mwan_kmod: Registering Netfilter steering hooks\n");
    err = nf_register_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
    if (err)
        return err;
    err = mwan_decap_l2_pqc_init();
    if (err) {
        nf_unregister_net_hooks(&init_net, mwan_nf_ops,
                                ARRAY_SIZE(mwan_nf_ops));
        return err;
    }
    err = mwan_mac_discovery_init();
    if (err) {
        mwan_decap_l2_pqc_cleanup();
        nf_unregister_net_hooks(&init_net, mwan_nf_ops,
                                ARRAY_SIZE(mwan_nf_ops));
        return err;
    }
    return 0;
}

void mwan_steer_cleanup(void) {
    pr_info("mwan_kmod: Unregistering steering hooks\n");
    mwan_mac_discovery_cleanup();
    nf_unregister_net_hooks(&init_net, mwan_nf_ops, ARRAY_SIZE(mwan_nf_ops));
    mwan_decap_l2_pqc_cleanup();
}
