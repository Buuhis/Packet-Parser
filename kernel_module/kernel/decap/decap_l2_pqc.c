#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <crypto/aead.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

static int l2_pqc_decrypt_skb(struct sk_buff *skb)
{
    struct mwan_config *cfg;
    struct mwan_crypto_hdr *chdr;
    int ciphertext_len;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    int err;

    pr_info("mwan_kmod DBG Decap: Entering l2_pqc_decrypt_skb, skb->len=%d\n", skb->len);

    // Validate minimum packet length for header + tag
    if (skb->len < MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN) {
        pr_warn("mwan_kmod DBG Decap: skb->len (%d) < min required (%d)\n",
                skb->len, MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN);
        return -EINVAL;
    }

    // Ensure skb head/fragments are write-safe
    if (skb_cow(skb, 0)) {
        pr_warn("mwan_kmod DBG Decap: skb_cow failed\n");
        return -ENOMEM;
    }

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb))) {
            pr_warn("mwan_kmod DBG Decap: skb_linearize failed\n");
            return -ENOMEM;
        }
    }

    chdr = (struct mwan_crypto_hdr *)skb->data;

    // Check custom magic identifier
    if (ntohs(chdr->magic) != MWAN_CRYPTO_MAGIC) {
        pr_warn("mwan_kmod DBG Decap: magic mismatch (got 0x%04x, expected 0x%04x)\n",
                ntohs(chdr->magic), MWAN_CRYPTO_MAGIC);
        return -EINVAL;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm || !cfg->encrypt_on) {
        pr_warn("mwan_kmod DBG Decap: config invalid or encrypt_on is false\n");
        rcu_read_unlock();
        return -ENODEV;
    }

    // Build IV: salt (4B) + sequence (8B)
    memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
    memcpy(iv_buf + MWAN_SALT_LEN, &chdr->seq, 8);

    // Extract plaintext length from proto and reserved fields
    u16 orig_len = ((u16)chdr->proto << 8) | chdr->reserved;
    ciphertext_len = orig_len + MWAN_GCM_TAG_LEN;

    pr_info("mwan_kmod DBG Decap: magic matched, seq=%llu, orig_len=%d, ciphertext_len=%d\n",
            be64_to_cpu(chdr->seq), orig_len, ciphertext_len);

    // Validate we have enough data in the skb
    if (skb->len < MWAN_CRYPTO_HDR_LEN + ciphertext_len) {
        pr_warn("mwan_kmod DBG Decap: skb->len (%d) < required (%d)\n",
                skb->len, MWAN_CRYPTO_HDR_LEN + ciphertext_len);
        rcu_read_unlock();
        return -EINVAL;
    }

    // Trim trailing Ethernet padding if any
    skb_trim(skb, MWAN_CRYPTO_HDR_LEN + ciphertext_len);

    // Allocate AEAD request
    req = aead_request_alloc(cfg->tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        return -ENOMEM;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], (u8 *)chdr, MWAN_CRYPTO_HDR_LEN); // AAD
        
        nents = skb_to_sgvec(skb, &sg[1], MWAN_CRYPTO_HDR_LEN, ciphertext_len);
        if (unlikely(nents < 0)) {
            pr_warn("mwan_kmod DBG Decap: skb_to_sgvec failed\n");
            aead_request_free(req);
            rcu_read_unlock();
            return -EIO;
        }

        aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
        aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

        err = crypto_aead_decrypt(req);
    }

    aead_request_free(req);

    if (err) {
        {
            static int decap_print_count = 0;
            if (decap_print_count < 5) {
                decap_print_count++;
                pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: err=%d, skb->len=%d, orig_len=%d, ciphertext_len=%d\n", 
                        decap_print_count, err, skb->len, orig_len, ciphertext_len);
                pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: key_len=%d, key=%*phN\n", 
                        decap_print_count, cfg->encrypt_key_len, cfg->encrypt_key_len, cfg->encrypt_key);
                pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: salt=%*phN\n", 
                        decap_print_count, MWAN_SALT_LEN, cfg->encrypt_salt);
                pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: iv=%*phN\n", 
                        decap_print_count, MWAN_GCM_IV_LEN, iv_buf);
                pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: chdr AAD=%*phN\n", 
                        decap_print_count, MWAN_CRYPTO_HDR_LEN, chdr);
                if (skb->len >= MWAN_CRYPTO_HDR_LEN + 16) {
                    pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: ciphertext (first 16B)=%*phN\n", 
                            decap_print_count, 16, skb->data + MWAN_CRYPTO_HDR_LEN);
                }
            }
        }
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d) - DROP\n", err);
        rcu_read_unlock();
        return err;
    }

    pr_info("mwan_kmod DBG Decap: Decryption SUCCESS!\n");

    // Decryption success: shift Ethernet header to close the crypto header gap
    memmove(skb->data + MWAN_CRYPTO_HDR_LEN - ETH_HLEN, skb->data - ETH_HLEN, ETH_HLEN);
    skb_pull(skb, MWAN_CRYPTO_HDR_LEN);
    skb_trim(skb, skb->len - MWAN_GCM_TAG_LEN);

    // Restore original Ethernet header type to IPv4
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

    if (!skb)
        return NET_RX_DROP;

    pr_info("mwan_kmod DBG Decap: RX handler called (dev: %s, orig_dev: %s)\n",
            dev ? dev->name : "NULL", orig_dev ? orig_dev->name : "NULL");

    ret = l2_pqc_decrypt_skb(skb);
    if (ret) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // Push packet back into the receive stack
    netif_rx(skb);
    return NET_RX_SUCCESS;
}

static unsigned int l2_pqc_bridge_decap_hook(void *priv,
                                            struct sk_buff *skb,
                                            const struct nf_hook_state *state)
{
    struct mwan_config *cfg;
    bool is_tunnel = false;
    int i, ret;

    if (!skb)
        return NF_ACCEPT;

    // Log hook entry for debugging
    pr_info_ratelimited("mwan_kmod DBG Decap: Bridge hook entry (in dev: %s, proto: 0x%04x)\n",
                        state->in ? state->in->name : "NULL",
                        ntohs(eth_hdr(skb)->h_proto));

    // Check if the packet has our EtherType (located at Ethernet Header protocol field)
    if (eth_hdr(skb)->h_proto != htons(MWAN_L2_PQC_ETHERTYPE))
        return NF_ACCEPT;

    pr_info("mwan_kmod DBG Decap: Bridge hook matched EtherType 0x88B5 on dev %s!\n",
            state->in ? state->in->name : "NULL");

    // We only process packets from our managed tunnel interfaces
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            pr_info("mwan_kmod DBG Decap: Comparing dev ifindex %d with tunnel[%d] ifindex %d\n",
                    state->in->ifindex, i, cfg->tunnels[i].ifindex);
            if (cfg->tunnels[i].ifindex == state->in->ifindex) {
                is_tunnel = true;
                break;
            }
        }
    }
    rcu_read_unlock();

    if (!is_tunnel) {
        pr_info("mwan_kmod DBG Decap: dev %s is NOT a managed tunnel!\n",
                state->in ? state->in->name : "NULL");
        return NF_ACCEPT;
    }

    pr_info("mwan_kmod DBG Decap: Proceeding with decryption for packet from dev %s\n",
            state->in->name);

    ret = l2_pqc_decrypt_skb(skb);
    if (ret) {
        pr_warn("mwan_kmod DBG Decap: Decryption failed, dropping packet\n");
        kfree_skb(skb);
        return NF_STOLEN;
    }

    pr_info("mwan_kmod DBG Decap: Hook returning NF_ACCEPT after successful decryption\n");
    return NF_ACCEPT;
}

static struct nf_hook_ops l2_pqc_decap_ops[] __read_mostly = {
    {
        .hook     = l2_pqc_bridge_decap_hook,
        .pf       = NFPROTO_BRIDGE,
        .hooknum  = NF_BR_PRE_ROUTING,
        .priority = NF_BR_PRI_FIRST,
    },
};

static struct packet_type l2_pqc_packet_type __read_mostly = {
    .type = cpu_to_be16(MWAN_L2_PQC_ETHERTYPE),
    .func = l2_pqc_rx_handler,
};

void mwan_decap_l2_pqc_init(void)
{
    dev_add_pack(&l2_pqc_packet_type);
    pr_info("mwan_kmod: Registered L2-PQC packet handler (0x%04x)\n", MWAN_L2_PQC_ETHERTYPE);

    if (nf_register_net_hooks(&init_net, l2_pqc_decap_ops, ARRAY_SIZE(l2_pqc_decap_ops)) < 0) {
        pr_err("mwan_kmod: Failed to register L2-PQC bridge Netfilter hook\n");
    } else {
        pr_info("mwan_kmod: Registered L2-PQC bridge Netfilter hook\n");
    }
}

void mwan_decap_l2_pqc_cleanup(void)
{
    dev_remove_pack(&l2_pqc_packet_type);
    pr_info("mwan_kmod: Unregistered L2-PQC packet handler\n");

    nf_unregister_net_hooks(&init_net, l2_pqc_decap_ops, ARRAY_SIZE(l2_pqc_decap_ops));
    pr_info("mwan_kmod: Unregistered L2-PQC bridge Netfilter hook\n");
}
