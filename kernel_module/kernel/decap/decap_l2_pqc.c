#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <crypto/aead.h>

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                            struct packet_type *pt, struct net_device *orig_dev)
{
    struct mwan_config *cfg;
    struct mwan_crypto_hdr *chdr;
    int ciphertext_len;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    int err;

    if (!skb)
        return NET_RX_DROP;

    // Validate minimum packet length for header + tag
    if (skb->len < MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Ensure skb head/fragments are write-safe
    if (skb_cow(skb, 0)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    chdr = (struct mwan_crypto_hdr *)skb->data;

    // Check custom magic identifier
    if (ntohs(chdr->magic) != MWAN_CRYPTO_MAGIC) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm || !cfg->encrypt_on) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Build IV: salt (4B) + sequence (8B)
    memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
    memcpy(iv_buf + MWAN_SALT_LEN, &chdr->seq, 8);

    ciphertext_len = skb->len - MWAN_CRYPTO_HDR_LEN;
    if (ciphertext_len < MWAN_GCM_TAG_LEN) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Allocate AEAD request
    req = aead_request_alloc(cfg->tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], (u8 *)chdr, MWAN_CRYPTO_HDR_LEN); // AAD
        
        nents = skb_to_sgvec(skb, &sg[1], MWAN_CRYPTO_HDR_LEN, ciphertext_len);
        if (unlikely(nents < 0)) {
            aead_request_free(req);
            rcu_read_unlock();
            kfree_skb(skb);
            return NET_RX_DROP;
        }

        aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
        aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

        err = crypto_aead_decrypt(req);
    }

    aead_request_free(req);

    if (err) {
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d) - DROP\n", err);
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Decryption success: remove crypto header and tag
    skb_pull(skb, MWAN_CRYPTO_HDR_LEN);
    skb_trim(skb, skb->len - MWAN_GCM_TAG_LEN);

    // Restore original Ethernet header type to IPv4
    struct ethhdr *eth = eth_hdr(skb);
    eth->h_proto = htons(ETH_P_IP);

    skb->protocol = htons(ETH_P_IP);
    skb_reset_network_header(skb);
    skb->ip_summed = CHECKSUM_NONE;

    rcu_read_unlock();

    // Push packet back into the receive stack
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
