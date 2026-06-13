#include "../../inc/crypto_layer2.h"
#include "../../inc/config.h"
#include "../../sig_encrypt/inc/pqc_handshake.h"
#include <string.h>
#include <stdio.h>
#include "../../sig_encrypt/inc/traffic_crypto.h"

#define MIN_ETH_PKT  (ETH_HEADER_SIZE + 8)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline __attribute__((always_inline))
int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 20)) return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0)) return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

static inline __attribute__((always_inline))
int verify_ipv6_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 40)) return 0;
    uint8_t next_hdr  = ip_payload[6];
    uint8_t hop_limit = ip_payload[7];
    if (unlikely(hop_limit == 0)) return 0;
    if (next_hdr == 6 || next_hdr == 17 || next_hdr == 58 ||
        next_hdr == 44 || next_hdr == 43 || next_hdr == 0 || next_hdr == 60)
        return 1;
    return 0;
}

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)) return -1;

    const int nonce_size = packet_crypto_get_nonce_size();

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t proto_flag;
    uint16_t fake_etype;

    if (likely(ether_type == 0x0800)) {
        proto_flag = PROTO_FLAG_IPV4;
        fake_etype = packet_crypto_get_fake_ethertype_ipv4();
    }
    else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
        fake_etype = packet_crypto_get_fake_ethertype_ipv6();
    }
    else return (int)pkt_len;

    if (unlikely(fake_etype == 0)) return (int)pkt_len;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const int mode = packet_crypto_get_mode();
    const int is_pqc = (mode == CRYPTO_MODE_PQC_GCM);
    const int is_gcm = (mode == CRYPTO_MODE_GCM); // STRICTLY GCM ONLY

    // CRITICAL FIX: Calculate the exact offset for payload
    const int l2_hdr_extra = is_pqc ? (nonce_size + 2) : nonce_size;
    const int l2_enc_start = 14 + l2_hdr_extra;

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    // Safely move payload to make room for tunnel header
    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);

    // Only write legacy counter if not PQC
    if (!is_pqc) {
        crypto_write_counter(packet, nonce, nonce_size, (uint8_t)(fake_etype >> 8),
                             packet_crypto_get_policy_id());
    }

    if (likely(is_gcm)) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                            packet + l2_enc_start, (int)payload_len, tag) != 0))
            return -1;
        memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + l2_hdr_extra + AES128_GCM_TAG_SIZE);
    }
    else if (packet_crypto_get_mode() == CRYPTO_MODE_PQC_GCM) {
        uint8_t pqc_nonce[12];
        trf_pqc_generate_nonce(pqc_nonce);

        uint8_t aad[12] __attribute__((aligned(64)));
        memcpy(aad, packet, 12);     // Src/Dst MAC

        int new_len = 0;
        if (trf_encrypt_payload_gcm(ctx->cipher_ctx_enc, key, pqc_nonce, 12, aad, 12, packet + l2_enc_start, (int)payload_len, &new_len) != TRF_PQC_OK)
            return -1;
        
        // Write tunnel header (Nonce + PolicyID + Magic)
        uint8_t *tun_hdr = packet + ETH_HEADER_SIZE;
        memcpy(tun_hdr, pqc_nonce, 12);
        tun_hdr[12] = packet_crypto_get_policy_id();
        tun_hdr[13] = 0xA5; // L4_TUNNEL_MAGIC

        // CRITICAL: Write fake ethertype to mark the packet for the receiver
        packet[12] = (uint8_t)(fake_etype >> 8);
        packet[13] = (uint8_t)(fake_etype & 0xFF);

        static uint32_t enc_count = 0;
        if (++enc_count % 1000 == 0) {
            printf("[PQC-ENC-DIAG] L2: etype=0x%04x, pi=%u\n", fake_etype, packet_crypto_get_policy_id());
            printf("[PQC-ENC-DIAG] Key: %02x%02x%02x%02x, Nonce: %02x%02x%02x%02x\n",
                   key[0], key[1], key[2], key[3], pqc_nonce[0], pqc_nonce[1], pqc_nonce[2], pqc_nonce[3]);
            printf("[PQC-ENC-DIAG] AAD: %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x\n",
                   aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7], aad[8], aad[9], aad[10], aad[11]);
            uint8_t *payload_ptr = packet + l2_enc_start;
            // Note: This is logged AFTER trf_encrypt_payload_gcm, so it's the Ciphertext
            printf("[PQC-ENC-DIAG] Ciphertext(first 8): %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   payload_ptr[0], payload_ptr[1], payload_ptr[2], payload_ptr[3], payload_ptr[4], payload_ptr[5], payload_ptr[6], payload_ptr[7]);
            // Tag is at the end of the encrypted payload
            uint8_t *tag_ptr = packet + ETH_HEADER_SIZE + nonce_size + 2 + payload_len;
            printf("[PQC-ENC-DIAG] Tag: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   tag_ptr[0], tag_ptr[1], tag_ptr[2], tag_ptr[3], tag_ptr[4], tag_ptr[5], tag_ptr[6], tag_ptr[7]);
            fflush(stdout);
        }

        return (int)(ETH_HEADER_SIZE + nonce_size + 2 + new_len);
    }
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (unlikely(crypto_aes_ctr_with_key(key, iv,
                                             packet + l2_enc_start, (int)payload_len) != 0))
            return -1;
        return (int)(pkt_len + l2_hdr_extra);
    }
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet)) return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int mode = packet_crypto_get_mode();
    const int is_pqc = (mode == CRYPTO_MODE_PQC_GCM);
    const int is_gcm = (mode == CRYPTO_MODE_GCM); // STRICTLY GCM ONLY

    // CRITICAL FIX: For PQC, we have 2 extra bytes (PolicyID + Magic)
    const int l2_hdr_extra = is_pqc ? (nonce_size + 2) : nonce_size;
    const int l2_enc_start = 14 + l2_hdr_extra;

    if (unlikely(pkt_len < (size_t)l2_enc_start)) return -1;

    const uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    const uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
    const uint8_t pkt_marker = packet[12];

    if (!((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
          (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)))) return (int)pkt_len;

    uint8_t policy_id;
    uint8_t proto_flag;
    uint8_t nonce[16];
    crypto_read_counter(packet, nonce_size, nonce, &policy_id, &proto_flag);
    (void)policy_id;
    const int is_ipv4 = (proto_flag == PROTO_FLAG_IPV4);
    
    const int nonce_len = is_pqc ? 12 : nonce_size;
    size_t enc_len = pkt_len - l2_enc_start;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (unlikely(pkt_len < (size_t)(l2_enc_start + AES128_GCM_TAG_SIZE))) return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);
    }

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup) memcpy(backup, packet + l2_enc_start, enc_len);

    uint8_t *work_ptr = packet + l2_enc_start;
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        if (k > 0 && has_backup) memcpy(work_ptr, backup, enc_len);

        if (mode == CRYPTO_MODE_GCM) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0)
                continue;
        }
        else if (mode == CRYPTO_MODE_PQC_GCM) {
            uint8_t aad[12] __attribute__((aligned(64)));
            memcpy(aad, packet, 12); // MACs
            
            static uint32_t dec_diag_cnt = 0;
            if (++dec_diag_cnt % 1000 == 0) {
                printf("[PQC-DEC-DIAG] Key: %02x%02x%02x%02x, Nonce: %02x%02x%02x%02x, enc_len=%zu\n",
                       key[0], key[1], key[2], key[3], nonce[0], nonce[1], nonce[2], nonce[3], enc_len);
                printf("[PQC-DEC-DIAG] AAD: %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x\n",
                       aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7], aad[8], aad[9], aad[10], aad[11]);
                printf("[PQC-DEC-DIAG] Ciphertext(first 8): %02x%02x%02x%02x%02x%02x%02x%02x\n",
                       work_ptr[0], work_ptr[1], work_ptr[2], work_ptr[3], work_ptr[4], work_ptr[5], work_ptr[6], work_ptr[7]);
                
                uint8_t *pqc_tag = work_ptr + enc_len - 16;
                printf("[PQC-DEC-DIAG] Tag: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                       pqc_tag[0], pqc_tag[1], pqc_tag[2], pqc_tag[3], pqc_tag[4], pqc_tag[5], pqc_tag[6], pqc_tag[7]);
                fflush(stdout);
            }

            int orig_len = 0;
            if (trf_decrypt_payload_gcm(ctx->cipher_ctx_dec, key, nonce, nonce_len, aad, 12, work_ptr, (int)enc_len, &orig_len) != TRF_PQC_OK)
                continue;
            enc_len = (size_t)orig_len;
        }
        else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0)
                continue;
            if (!(is_ipv4 ? verify_ipv4_after_decrypt(work_ptr, enc_len)
                          : verify_ipv6_after_decrypt(work_ptr, enc_len))) {
                continue;
            }
        }

        if (key_order[k] == KEY_SLOT_CURRENT && ctx->key_slots_valid[KEY_SLOT_PREV]) {
            ctx->key_slots_valid[KEY_SLOT_PREV] = false;
            sig_pqc_discard_prev_key(ctx->policy_id);
        }

        // Success! Promote key if slot next
        if (key_order[k] == KEY_SLOT_NEXT) {
            memcpy(ctx->keys[KEY_SLOT_PREV], ctx->keys[KEY_SLOT_CURRENT], AES_MAX_KEY_SIZE);
            ctx->key_ids[KEY_SLOT_PREV] = ctx->key_ids[KEY_SLOT_CURRENT];
            ctx->key_slots_valid[KEY_SLOT_PREV] = ctx->key_slots_valid[KEY_SLOT_CURRENT];

            memcpy(ctx->keys[KEY_SLOT_CURRENT], ctx->keys[KEY_SLOT_NEXT], AES_MAX_KEY_SIZE);
            ctx->key_ids[KEY_SLOT_CURRENT] = ctx->key_ids[KEY_SLOT_NEXT];
            ctx->key_slots_valid[KEY_SLOT_CURRENT] = true;

            ctx->key_slots_valid[KEY_SLOT_NEXT] = false;
            printf("[PQC-DATA] L2 Implicit key promotion: NEXT -> CURRENT for Policy %d!\n", ctx->policy_id);
            sig_pqc_promote_responder_key(ctx->policy_id);
        }
        goto decrypt_success;
    }
    return -1;

decrypt_success:
    {
        int has_ethertype = (work_ptr[0] == 0x08 && work_ptr[1] == 0x00) ||
                            (work_ptr[0] == 0x86 && work_ptr[1] == 0xDD);
        if (has_ethertype) {
            packet[12] = work_ptr[0];
            packet[13] = work_ptr[1];
            memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
            return (int)(ETH_HEADER_SIZE + enc_len - 2);
        } else {
            packet[12] = is_ipv4 ? 0x08 : 0x86;
            packet[13] = is_ipv4 ? 0x00 : 0xDD;
            memmove(packet + ETH_HEADER_SIZE, work_ptr, enc_len);
            return (int)(ETH_HEADER_SIZE + enc_len);
        }
    }
}

