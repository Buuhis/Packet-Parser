#include "../../inc/crypto_layer2.h"
#include "../../inc/config.h"
#include <string.h>
#include <stdio.h>

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
    const int l2_hdr_extra = nonce_size;
    const int l2_enc_start = 14 + nonce_size;

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
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);

    crypto_write_counter(packet, nonce, nonce_size, (uint8_t)(fake_etype >> 8),
                         packet_crypto_get_policy_id());

    if (likely(is_gcm)) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                            packet + l2_enc_start, (int)payload_len, tag) != 0))
            return -1;
        memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + l2_hdr_extra + AES128_GCM_TAG_SIZE);
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
    const int l2_enc_start = 14 + nonce_size;

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
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    const int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t enc_len = pkt_len - l2_enc_start;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (unlikely(pkt_len < (size_t)(l2_enc_start + AES128_GCM_TAG_SIZE))) return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);
    }

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr = packet + l2_enc_start;

    if (likely(is_gcm)) {
        if (likely(crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) == 0)) {
            goto decrypt_success;
        }
    }
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (likely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) == 0)) {
            if (likely(is_ipv4 ? verify_ipv4_after_decrypt(work_ptr, enc_len)
                               : verify_ipv6_after_decrypt(work_ptr, enc_len))) {
                goto decrypt_success;
            }
        }
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

