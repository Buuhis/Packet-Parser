#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <crypto/aead.h>
#include <linux/netfilter.h>
#include <linux/ktime.h>

#define MWAN_L2_HDR_LEN 8 /* 8 Bytes Sequence Number */

static int l2_pqc_decrypt_skb(struct sk_buff *skb)
{
    struct mwan_config *cfg;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    int err, ciphertext_len, plaintext_len;
    u64 seq;

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb)))
            return -ENOMEM;
    }
    if (skb_cow(skb, 0))
        return -ENOMEM;

    // Packet must have at least 8B Seq + 16B GCM Tag = 24 Bytes
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm || !cfg->encrypt_on) {
        rcu_read_unlock();
        return -ENODEV;
    }

    // Read 8-byte Sequence Number from start of skb->data
    seq = be64_to_cpu(*(__be64 *)skb->data);

    // Rebuild IV: 4B Salt + 8B Sequence Number
    memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv_buf + MWAN_SALT_LEN) = cpu_to_be64(seq);

    ciphertext_len = skb->len - MWAN_L2_HDR_LEN; // Everything after 8B Seq header
    plaintext_len = ciphertext_len - MWAN_GCM_TAG_LEN; // Original IP packet len

    req = aead_request_alloc(cfg->tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], skb->data, MWAN_L2_HDR_LEN); // AAD = 8B Seq

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
    // Move Ethernet header 8 bytes forward to overwrite the 8-byte Seq header
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

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;
    u64 ns_entry, ns_exit;

    if (!skb)
        return NET_RX_DROP;

    ns_entry = ktime_get_real_ns();
    pr_info("mwan_kmod DBG Decap [ENTRY]: skb_ptr=%px, time_ns=%llu, dev=%s, len=%d, proto=0x%04x (ENCRYPTED 88b5)\n",
            skb, ns_entry, dev ? dev->name : "NULL", skb->len, ntohs(skb->protocol));

    ret = l2_pqc_decrypt_skb(skb);
    if (ret < 0) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    ns_exit = ktime_get_real_ns();
    pr_info("mwan_kmod DBG Decap [RE-INJECT netif_rx]: skb_ptr=%px, time_ns=%llu, delta_ns=%llu, dev=%s, len=%d, proto=0x%04x (DECRYPTED 0800)\n",
            skb, ns_exit, ns_exit - ns_entry, skb->dev ? skb->dev->name : "NULL", skb->len, ntohs(skb->protocol));

    // Re-inject clean plaintext packet into the receive stack for kernel IP routing
    netif_rx(skb);
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
