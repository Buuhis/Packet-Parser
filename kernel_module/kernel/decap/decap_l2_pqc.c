#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <crypto/aead.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

#define L2_PQC_DECAP_SUCCESS 0
#define L2_PQC_DECAP_BYPASS  1

static int l2_pqc_decrypt_skb(struct sk_buff *skb)
{
    struct mwan_config *cfg;
    int ciphertext_len;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    int err;
    int pulled_bytes = 0;

    // Linearize and COW first so that skb->data is contiguous and safe to read
    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb))) {
            pr_warn("mwan_kmod DBG Decap: skb_linearize failed at entry\n");
            return -ENOMEM;
        }
    }
    if (skb_cow(skb, 0)) {
        pr_warn("mwan_kmod DBG Decap: skb_cow failed at entry\n");
        return -ENOMEM;
    }

    pr_info_ratelimited("mwan_kmod DBG Decap: entered. skb->len=%d, dev=%s\n", skb->len, skb->dev ? skb->dev->name : "NULL");

    // Robust Dynamic Offset Alignment:
    // Search for signature 0x88 0xB5 0x4D 0x57 ([EtherType 0x88B5] + [Magic 0x4D57])
    // or direct Magic 0x4D 0x57 at offset 0.
    pulled_bytes = -1;
    if (skb->len >= 2 && skb->data[0] == 0x4D && skb->data[1] == 0x57) {
        pulled_bytes = 0;
    } else {
        int max_search = (skb->len < 32) ? (skb->len - 3) : 28;
        int i;
        for (i = 0; i < max_search; i++) {
            if (skb->data[i] == 0x88 && skb->data[i+1] == 0xB5 &&
                skb->data[i+2] == 0x4D && skb->data[i+3] == 0x57) {
                pulled_bytes = i + 2;
                skb_pull(skb, i + 2);
                break;
            }
        }
    }

    if (pulled_bytes < 0) {
        pr_info_ratelimited("mwan_kmod DBG Decap: Signature search failed, bypass. First 14B: %*phN\n", 
                            skb->len < 14 ? skb->len : 14, skb->data);
        return L2_PQC_DECAP_BYPASS;
    }

    // Check if the remaining packet is too short to be an encrypted packet (12B header + 16B tag = 28B minimum).
    // Discovery/handshake/keepalive frames are short and will be bypassed here.
    if (skb->len < MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN) {
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return L2_PQC_DECAP_BYPASS;
    }

    // Check custom magic identifier
    u16 magic = ((u16)skb->data[0] << 8) | skb->data[1];
    if (magic != MWAN_CRYPTO_MAGIC) {
        pr_info_ratelimited("mwan_kmod DBG Decap: Magic mismatch: 0x%04x (expected 0x%04x)\n", magic, MWAN_CRYPTO_MAGIC);
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return L2_PQC_DECAP_BYPASS;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm || !cfg->encrypt_on) {
        pr_warn("mwan_kmod DBG Decap: config invalid or encrypt_on is false\n");
        rcu_read_unlock();
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return -ENODEV;
    }

    // Build IV: salt (4B) + sequence (8B) from skb->data+4
    memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
    memcpy(iv_buf + MWAN_SALT_LEN, skb->data + 4, 8);

    // Extract plaintext length from proto and reserved fields (bytes 2 & 3)
    u8 proto = skb->data[2];
    u8 reserved = skb->data[3];
    u16 orig_len = ((u16)proto << 8) | reserved;
    ciphertext_len = orig_len + MWAN_GCM_TAG_LEN;

    // Validate we have enough data in the skb
    if (skb->len < MWAN_CRYPTO_HDR_LEN + ciphertext_len) {
        static int decap_len_err_count = 0;
        if (decap_len_err_count < 10) {
            decap_len_err_count++;
            int dump_len = skb->len < 64 ? skb->len : 64;
            pr_warn("mwan_kmod DBG Decap: skb->len (%d) < required (%d) [orig_len=%d], dev=%s\n",
                    skb->len, MWAN_CRYPTO_HDR_LEN + ciphertext_len, orig_len,
                    skb->dev ? skb->dev->name : "NULL");
            pr_warn("mwan_kmod DBG Decap: data=%*phN\n", dump_len, skb->data);
            if (skb_mac_header_was_set(skb)) {
                pr_warn("mwan_kmod DBG Decap: mac_header=%*phN\n", 14, skb_mac_header(skb));
            }
        }
        rcu_read_unlock();
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return L2_PQC_DECAP_BYPASS;
    }

    // Trim trailing Ethernet padding if any
    skb_trim(skb, MWAN_CRYPTO_HDR_LEN + ciphertext_len);

    // Allocate AEAD request
    req = aead_request_alloc(cfg->tfm, GFP_ATOMIC);
    if (!req) {
        rcu_read_unlock();
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return -ENOMEM;
    }

    {
        struct scatterlist sg[2];

        sg_init_table(sg, 2);
        sg_set_buf(&sg[0], skb->data, MWAN_CRYPTO_HDR_LEN); // AAD
        sg_set_buf(&sg[1], skb->data + MWAN_CRYPTO_HDR_LEN, ciphertext_len); // Ciphertext + Tag

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
                        decap_print_count, MWAN_CRYPTO_HDR_LEN, skb->data);
                if (skb->len >= MWAN_CRYPTO_HDR_LEN + 16) {
                    pr_warn("mwan_kmod DBG [Decap L2 PQC %d]: ciphertext (first 16B)=%*phN\n", 
                            decap_print_count, 16, skb->data + MWAN_CRYPTO_HDR_LEN);
                }
            }
        }
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d) - DROP\n", err);
        rcu_read_unlock();
        if (pulled_bytes > 0) {
            skb_push(skb, pulled_bytes);
        }
        return err;
    }

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

    {
        struct iphdr *iph = ip_hdr(skb);
        u16 old_check = iph->check;
        u16 calc_check;
        iph->check = 0;
        calc_check = ip_fast_csum((u8 *)iph, iph->ihl);
        iph->check = old_check;

        pr_info("mwan_kmod DBG Decap SUCCESS: Dst MAC=%pM, Src MAC=%pM, Dst IP=%pI4, Src IP=%pI4, proto=%d, cksum_hdr=0x%04x, cksum_calc=0x%04x (%s)\n",
                eth->h_dest, eth->h_source, &iph->daddr, &iph->saddr, iph->protocol,
                ntohs(old_check), ntohs(calc_check),
                (old_check == calc_check) ? "VALID" : "INVALID");
    }

    rcu_read_unlock();
    return L2_PQC_DECAP_SUCCESS;
}

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    if (!skb)
        return NET_RX_DROP;

    ret = l2_pqc_decrypt_skb(skb);
    if (ret < 0) {
        kfree_skb(skb);
        return NET_RX_DROP;
    } else if (ret == L2_PQC_DECAP_BYPASS) {
        consume_skb(skb);
        return NET_RX_SUCCESS;
    }

    // Push packet back into the receive stack
    pr_info("mwan_kmod DBG Decap: calling netif_rx on skb\n");
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

    // Check if the packet has our EtherType (located at Ethernet Header protocol field)
    if (eth_hdr(skb)->h_proto != htons(MWAN_L2_PQC_ETHERTYPE))
        return NF_ACCEPT;

    // We only process packets from our managed tunnel interfaces
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            if (cfg->tunnels[i].ifindex == state->in->ifindex) {
                is_tunnel = true;
                break;
            }
        }
    }
    rcu_read_unlock();

    if (!is_tunnel) {
        return NF_ACCEPT;
    }

    ret = l2_pqc_decrypt_skb(skb);
    if (ret < 0) {
        kfree_skb(skb);
        return NF_STOLEN;
    } else if (ret == L2_PQC_DECAP_BYPASS) {
        return NF_ACCEPT;
    }

    // Decryption succeeded: move skb->data back to the restored Ethernet header
    skb_push(skb, ETH_HLEN);

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
    pr_info("mwan_kmod: Registered L2-PQC packet handler (0x%04x) - ADAPTIVE_ETH_PULL_V4\n", MWAN_L2_PQC_ETHERTYPE);

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
