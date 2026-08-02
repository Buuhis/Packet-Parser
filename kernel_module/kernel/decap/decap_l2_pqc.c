#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <crypto/aead.h>
#include <linux/netfilter.h>

#define MWAN_L2_HDR_LEN 16 /* 16 Bytes AAD for RFC4106 */

static int l2_pqc_decrypt_skb(struct sk_buff *skb, u32 *out_flow_id, u64 *out_flow_seq)
{
    struct mwan_config *cfg;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    int err, ciphertext_len;
    struct mwan_l2_pqc_hdr *l2_hdr;

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb)))
            return -ENOMEM;
    }
    if (skb_cow(skb, 0))
        return -ENOMEM;

    // Packet must have at least 16B L2 Header + 16B GCM Tag = 32 Bytes
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm || !cfg->encrypt_on) {
        rcu_read_unlock();
        return -ENODEV;
    }

    // Read MACsec-style L2-PQC Header (4B Flow_ID + 8B Flow_Seq)
    l2_hdr = (struct mwan_l2_pqc_hdr *)skb->data;
    if (out_flow_id) *out_flow_id = be32_to_cpu(l2_hdr->flow_id);
    if (out_flow_seq) *out_flow_seq = be64_to_cpu(l2_hdr->flow_seq);

    // RFC 4106 IV: 8 Bytes Flow Sequence Number
    *(__be64 *)iv_buf = l2_hdr->flow_seq;

    ciphertext_len = skb->len - MWAN_L2_HDR_LEN;

    req = aead_request_alloc(cfg->tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], skb->data, MWAN_L2_HDR_LEN); // AAD = 16B L2 Header

        nents = skb_to_sgvec(skb, &sg[1], MWAN_L2_HDR_LEN, ciphertext_len);
        if (unlikely(nents < 0)) {
            aead_request_free(req);
            rcu_read_unlock();
            return -EINVAL;
        }

        aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
        aead_request_set_ad(req, MWAN_L2_HDR_LEN);

        err = crypto_aead_decrypt(req);
    }

    aead_request_free(req);

    if (err) {
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d)\n", err);
        rcu_read_unlock();
        return err;
    }

    // Decryption success!
    if (unlikely(skb_cow(skb, ETH_HLEN))) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    // Move Ethernet header 16 bytes forward to overwrite the 16-byte L2 Header
    memmove(skb->data + MWAN_L2_HDR_LEN - ETH_HLEN, skb->data - ETH_HLEN, ETH_HLEN);
    skb_pull(skb, MWAN_L2_HDR_LEN);
    skb_trim(skb, skb->len - MWAN_GCM_TAG_LEN);

    // Restore Ethernet Header EtherType to IPv4 (0x0800)
    skb_set_mac_header(skb, -ETH_HLEN);
    struct ethhdr *eth = eth_hdr(skb);
    eth->h_proto = htons(ETH_P_IP);

    skb->protocol = htons(ETH_P_IP);
    skb_reset_network_header(skb);
    skb->ip_summed = CHECKSUM_NONE;

    rcu_read_unlock();
    return 0;
}

void mwan_reorder_timeout(struct timer_list *t)
{
    struct mwan_config *cfg = container_of(t, struct mwan_config, reorder_timer);
    bool restart = false;
    int f;

    for (f = 0; f < MWAN_FLOW_TABLE_SIZE; f++) {
        struct mwan_per_flow_reorder *flow = &cfg->flow_reorder[f];
        spin_lock_bh(&flow->drain_lock);

        while (1) {
            u32 slot = (u32)(atomic64_read(&flow->expected_seq) & MWAN_FLOW_RING_MASK);
            struct sk_buff *skb = flow->ring[slot];

            if (skb) {
                flow->ring[slot] = NULL;
                flow->slot_time[slot] = 0;
                atomic64_inc(&flow->expected_seq);
                netif_rx(skb);
            } else if (flow->slot_time[slot] &&
                       time_after(jiffies, flow->slot_time[slot] + MWAN_REORDER_TIMEOUT)) {
                /* Timeout: lost packet in this flow -> skip slot */
                flow->slot_time[slot] = 0;
                atomic64_inc(&flow->expected_seq);
            } else {
                break;
            }
        }

        for (int i = 0; i < MWAN_FLOW_RING_SIZE; i++) {
            if (flow->ring[i]) {
                restart = true;
                break;
            }
        }
        spin_unlock_bh(&flow->drain_lock);
    }

    if (restart)
        mod_timer(&cfg->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
}

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev)
{
    (void)dev;
    (void)pt;
    (void)orig_dev;
    struct mwan_config *cfg;
    u32 flow_id = 0;
    u64 flow_seq = 0;
    int ret;

    if (!skb)
        return NET_RX_DROP;

    if (skb->len < MWAN_L2_HDR_LEN) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    ret = l2_pqc_decrypt_skb(skb, &flow_id, &flow_seq);
    if (ret < 0) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg && cfg->encrypt_on) {
        u32 flow_idx = flow_id & (MWAN_FLOW_TABLE_SIZE - 1);
        struct mwan_per_flow_reorder *flow_reorder = &cfg->flow_reorder[flow_idx];

        u64 current_exp = (u64)atomic64_read(&flow_reorder->expected_seq);
        
        /* Per-Flow First-Packet Auto-Sync: 0ms TCP Handshake start */
        if (unlikely(current_exp == 1 || flow_seq > current_exp + 128)) {
            atomic64_set(&flow_reorder->expected_seq, flow_seq);
        }

        spin_lock_bh(&flow_reorder->drain_lock);

        u32 slot = flow_seq & MWAN_FLOW_RING_MASK;

        /* If slot already contains a packet (duplicate/overwrite), flush old packet first */
        if (unlikely(flow_reorder->ring[slot] != NULL)) {
            netif_rx(flow_reorder->ring[slot]);
            flow_reorder->ring[slot] = NULL;
        }

        flow_reorder->ring[slot] = skb;
        flow_reorder->slot_time[slot] = jiffies;

        /* Drain per-flow inline while holding per-flow drain_lock */
        while (1) {
            u64 expected = atomic64_read(&flow_reorder->expected_seq);
            u32 s = expected & MWAN_FLOW_RING_MASK;
            struct sk_buff *pending = flow_reorder->ring[s];

            if (!pending)
                break;

            flow_reorder->ring[s] = NULL;
            flow_reorder->slot_time[s] = 0;
            atomic64_inc(&flow_reorder->expected_seq);
            netif_rx(pending);
        }

        spin_unlock_bh(&flow_reorder->drain_lock);

        mod_timer(&cfg->reorder_timer, jiffies + MWAN_REORDER_TIMEOUT);
    } else {
        netif_rx(skb);
    }
    rcu_read_unlock();

    return NET_RX_SUCCESS;
}

static struct packet_type l2_pqc_packet_type __read_mostly = {
    .type = cpu_to_be16(MWAN_L2_PQC_ETHERTYPE),
    .func = l2_pqc_rx_handler,
};

void mwan_decap_l2_pqc_init(void)
{
    dev_add_pack(&l2_pqc_packet_type);
    pr_info("mwan_kmod: Registered L2-PQC packet handler (0x%04x)\n", MWAN_L2_PQC_ETHERTYPE);
}

void mwan_decap_l2_pqc_cleanup(void)
{
    dev_remove_pack(&l2_pqc_packet_type);
    pr_info("mwan_kmod: Unregistered L2-PQC packet handler\n");
}
