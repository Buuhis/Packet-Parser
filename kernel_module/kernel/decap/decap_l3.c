#include "../mwan_steer.h"
#include "../mwan_proto.h"
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

/**
 * mwan_handle_decap_l3 - Decrypt an inbound MWAN-encrypted packet (AES-GCM)
 * @skb:  The inbound packet (must be inside rcu_read_lock)
 * @cfg:  The current MWAN config (RCU-dereferenced by caller)
 *
 * Returns:
 *   MWAN_DECAP_CONTINUE — Packet ready for further processing (decrypted or not encrypted)
 *   NF_ACCEPT           — Non-fatal error, let kernel handle normally
 *   NF_DROP             — Fatal error (auth fail, async crypto), drop packet
 *
 * Note: Caller holds rcu_read_lock() and is responsible for rcu_read_unlock().
 */
int mwan_handle_decap_l3(struct sk_buff *skb, struct mwan_config *cfg)
{
    struct iphdr *iph;
    int iph_len;
    int total_len;
    struct mwan_crypto_hdr *chdr;
    u8 *payload_after_chdr;
    int ciphertext_len;
    u8 iv_buf[MWAN_GCM_IV_LEN];
    struct aead_request *req;
    struct crypto_aead *tfm;
    struct scatterlist sg[2];
    int err;

    iph = ip_hdr(skb);
    if (iph->protocol != MWAN_FAKE_PROTOCOL)
        return MWAN_DECAP_CONTINUE;

    iph_len = iph->ihl * 4;
    total_len = ntohs(iph->tot_len);

    /* Packet too small to contain crypto header + tag → not encrypted */
    if (total_len < iph_len + MWAN_CRYPTO_HDR_LEN + MWAN_GCM_TAG_LEN)
        return MWAN_DECAP_CONTINUE;

    if (!pskb_may_pull(skb, iph_len + MWAN_CRYPTO_HDR_LEN))
        return NF_ACCEPT;

    /* Linearize for crypto operation */
    if (skb_linearize(skb))
        return NF_ACCEPT;

    /* Make writable */
    if (skb_ensure_writable(skb, total_len))
        return NF_ACCEPT;

    /* Reload pointers after linearize/writable */
    iph = ip_hdr(skb);
    chdr = (struct mwan_crypto_hdr *)((u8 *)iph + iph_len);

    /* Check magic — if not ours, it's not an encrypted MWAN packet */
    if (ntohs(chdr->magic) != MWAN_CRYPTO_MAGIC)
        return MWAN_DECAP_CONTINUE;

    /* Generation 0 is accepted as current for rolling compatibility with
     * packets emitted before key IDs were carried in the reserved byte. */
    if (chdr->key_id == 0 || chdr->key_id == cfg->key_id) {
        tfm = cfg->tfm;
    } else if (cfg->prev_key_valid &&
               chdr->key_id == cfg->prev_key_id) {
        tfm = cfg->prev_tfm;
    } else {
        return NF_DROP;
    }
    if (!tfm)
        return NF_DROP;

    /* Build IV: salt (4B) + sequence (8B) */
    memcpy(iv_buf, cfg->encrypt_salt, MWAN_SALT_LEN);
    memcpy(iv_buf + MWAN_SALT_LEN, &chdr->seq, 8);

    /* Calculate ciphertext length (includes GCM tag) */
    ciphertext_len = total_len - iph_len - MWAN_CRYPTO_HDR_LEN;
    if (ciphertext_len < MWAN_GCM_TAG_LEN) {
        pr_warn_ratelimited("mwan_kmod: RX decrypt: invalid ciphertext length\n");
        return NF_DROP;
    }

    payload_after_chdr = (u8 *)iph + iph_len + MWAN_CRYPTO_HDR_LEN;

    /* Setup AEAD request for decryption
     * AAD = MWAN Crypto Header (10B) — immutable, contains sequence
     * Ciphertext + Tag follow immediately in memory */
    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req)
        return NF_ACCEPT;

    sg_init_table(sg, 2);
    sg_set_buf(&sg[0], (u8 *)chdr, MWAN_CRYPTO_HDR_LEN);       /* AAD */
    sg_set_buf(&sg[1], payload_after_chdr, ciphertext_len);     /* Ciphertext + Tag */

    aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
    aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

    err = crypto_aead_decrypt(req);

    if (err == -EINPROGRESS || err == -EBUSY) {
        /* Driver is async, can't wait in SoftIRQ. Drop to avoid UAF crash. */
        pr_warn_ratelimited("mwan_kmod: Async crypto detected in RX - dropping packet to avoid crash\n");
        aead_request_free(req);
        return NF_DROP;
    }

    aead_request_free(req);

    if (err) {
        pr_warn_ratelimited("mwan_kmod: RX decrypt FAILED (auth tag mismatch, err=%d) — DROP\n", err);
        return NF_DROP;
    }

    /* Decryption success: Restore the original protocol */
    iph->protocol = chdr->proto;

    /* Remove crypto header and tag.
     * Shift decrypted payload up to overwrite crypto header. */
    {
        int plaintext_len = ciphertext_len - MWAN_GCM_TAG_LEN;
        u8 *src = (u8 *)iph + iph_len + MWAN_CRYPTO_HDR_LEN;
        u8 *dst = (u8 *)iph + iph_len;

        memmove(dst, src, plaintext_len);

        /* Update IP header: remove crypto overhead */
        iph->tot_len = htons(iph_len + plaintext_len);
        iph->check = 0;
        iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

        /* Trim skb to remove crypto header + tag */
        skb_trim(skb, iph_len + plaintext_len);

        skb_set_transport_header(skb, iph_len);
        
        /* Recalculate TCP/UDP checksum in software and set ip_summed to CHECKSUM_NONE */
        {
            int tcplen = plaintext_len;
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)((u8 *)iph + iph_len);
                if (pskb_may_pull(skb, iph_len + sizeof(struct tcphdr))) {
                    iph = ip_hdr(skb);
                    tcph = (struct tcphdr *)((u8 *)iph + iph_len);
                    tcph->check = 0;
                    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                                                    skb_checksum(skb, iph_len, tcplen, 0));
                    skb->ip_summed = CHECKSUM_NONE;
                } else {
                    skb->ip_summed = CHECKSUM_UNNECESSARY;
                }
            } else if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)((u8 *)iph + iph_len);
                if (pskb_may_pull(skb, iph_len + sizeof(struct udphdr))) {
                    iph = ip_hdr(skb);
                    udph = (struct udphdr *)((u8 *)iph + iph_len);
                    udph->check = 0;
                    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_UDP,
                                                    skb_checksum(skb, iph_len, tcplen, 0));
                    if (udph->check == 0) udph->check = 0xffff;
                    skb->ip_summed = CHECKSUM_NONE;
                } else {
                    skb->ip_summed = CHECKSUM_UNNECESSARY;
                }
            } else {
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }
    }

    return MWAN_DECAP_CONTINUE;
}
