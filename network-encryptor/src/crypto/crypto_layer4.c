#include "../../inc/crypto_layer4.h"
#include "../../inc/config.h"
#include "../../inc/fragment.h"
#include "../../sig_encrypt/inc/traffic_crypto.h"
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

#define L4_TUNNEL_MAGIC    0xA5
#define L4_FRAG_MAGIC      (L4_TUNNEL_MAGIC | FRAG_FLAG_BIT)

#define L4_MAX_FRAME      1514

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_PSH  0x08
#define TCP_SEQ_OFF   4
#define TCP_FLAGS_OFF 13
#define TCP_CKSUM_OFF 16
#define UDP_CKSUM_OFF 6

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce,
                                    int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = L4_TUNNEL_MAGIC;
}

static void l4_read_tunnel_header(const uint8_t *buf, int nonce_size,
                                   uint8_t *nonce_out, uint8_t *policy_id,
                                   uint8_t *proto_flag) {
    memcpy(nonce_out, buf, nonce_size);
    if (policy_id) *policy_id = buf[nonce_size];
    if (proto_flag) *proto_flag = nonce_out[0] >> 7;
}

static void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce,
                                         int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = L4_FRAG_MAGIC;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size) {
    // Check for Magic Byte at the correct offset (Nonce + PolicyID slot)
    if (buf[nonce_size + 1] != L4_TUNNEL_MAGIC && buf[nonce_size + 1] != L4_FRAG_MAGIC) 
        return 0;
    
    // We removed the (buf[0] & 0x80) check because PQC nonces are random 
    // and can safely start with a 1 bit.
    return 1;
}

static int get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto, size_t remaining) {
    if (ip_proto == 6) {
        if (remaining < 20) return -1;
        int data_off = ((transport_hdr[12] >> 4) & 0x0F) * 4;
        if (data_off < 20 || (size_t)data_off > remaining) return -1;
        return data_off;
    } 
    
    else if (ip_proto == 17) {
        if (remaining < 8) return -1;
        return 8;
    }
    return -1;
}

int crypto_layer4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto, size_t remaining) {
    return get_transport_hdr_size(transport_hdr, ip_proto, remaining);
}

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len) {
    if (!pkt || pkt_len < 14)
        return -1;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800)
        return 14;
    if (et == 0x8100) {
        if (pkt_len < 18)
            return -1;
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (et == 0x0800)
            return 18;
        if (et == 0x8100 && pkt_len >= 22) {
            et = ((uint16_t)pkt[20] << 8) | pkt[21];
            if (et == 0x0800)
                return 22;
        }
    }
    return -1;
}

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17)
        return (int)pkt_len;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    size_t remaining = pkt_len - (size_t)transport_off;

    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return (int)pkt_len;

  
    int enc_off = transport_off + transport_hdr_size;
    size_t enc_len = pkt_len - (size_t)enc_off;
    if (enc_len == 0)
        return (int)pkt_len;

    int mode = packet_crypto_get_mode();
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint32_t counter = packet_crypto_next_counter();

    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    if (mode == CRYPTO_MODE_GCM) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)enc_len, tag) != 0)
            return -1;
        memmove(packet + enc_off + tunnel_hdr_size, packet + enc_off, enc_len);
        memcpy(packet + enc_off + tunnel_hdr_size + enc_len, tag, AES128_GCM_TAG_SIZE);
    } else if (mode == CRYPTO_MODE_PQC_GCM) {
        int new_len = 0;
        uint8_t pqc_nonce[12];
        trf_pqc_generate_nonce(pqc_nonce);

        uint8_t aad[12] __attribute__((aligned(64)));
        struct iphdr *ip = (struct iphdr *)(packet + l3_off);
        uint16_t src_port = 0, dst_port = 0;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + transport_off);
            src_port = tcp->source;
            dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(packet + transport_off);
            src_port = udp->source;
            dst_port = udp->dest;
        }

        memcpy(aad, &ip->saddr, 4);
        memcpy(aad + 4, &ip->daddr, 4);
        memcpy(aad + 8, &src_port, 2);
        memcpy(aad + 10, &dst_port, 2);

        if (trf_encrypt_payload_gcm(ctx->cipher_ctx_enc, key, pqc_nonce, 12, aad, 12, packet + enc_off, (int)enc_len, &new_len) != TRF_PQC_OK)
            return -1;
        
        // DEBUG DUMP AAD/NONCE/KEY
        printf("[DEBUG-ENC] AAD: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X\n",
                aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7], aad[8], aad[9], aad[10], aad[11]);
        printf("[DEBUG-ENC] Nonce: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                pqc_nonce[0], pqc_nonce[1], pqc_nonce[2], pqc_nonce[3], pqc_nonce[4], pqc_nonce[5],
                pqc_nonce[6], pqc_nonce[7], pqc_nonce[8], pqc_nonce[9], pqc_nonce[10], pqc_nonce[11]);
        printf("[DEBUG-ENC] Key(first 4): %02X%02X%02X%02X\n",
                key[0], key[1], key[2], key[3]);
        
        int tunnel_hdr_size_local = packet_crypto_get_nonce_size() + 2;
        memmove(packet + enc_off + tunnel_hdr_size_local, packet + enc_off, new_len);
        l4_write_tunnel_header(packet + enc_off, pqc_nonce, 12); 

        // DEBUG LOG:
        printf("[DEBUG-ENC] PQC-GCM Encrypted: enc_off=%d, hdr_size=%d, payload_new_len=%d, magic_at_%d=0x%02X\n", 
                enc_off, tunnel_hdr_size_local, new_len, enc_off + 13, packet[enc_off + 13]);
        
        enc_len = (size_t)new_len;
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)enc_len) != 0)
            return -1;
        memmove(packet + enc_off + tunnel_hdr_size, packet + enc_off, enc_len);
        l4_write_tunnel_header(packet + enc_off, nonce, nonce_size);
    }

    int total_overhead = tunnel_hdr_size;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) total_overhead += AES128_GCM_TAG_SIZE;
    uint16_t old_totlen = ((uint16_t)packet[l3_off + 2] << 8) | packet[l3_off + 3];
    uint16_t new_totlen = old_totlen + (uint16_t)total_overhead;
    packet[l3_off + 2] = (uint8_t)(new_totlen >> 8);
    packet[l3_off + 3] = (uint8_t)(new_totlen & 0xFF);
    packet[l3_off + 10] = 0;
    packet[l3_off + 11] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(packet + l3_off, ip_hdr_len);
    packet[l3_off + 10] = (uint8_t)(cksum >> 8);
    packet[l3_off + 11] = (uint8_t)(cksum & 0xFF);


    size_t new_pkt_len = pkt_len + (size_t)total_overhead;
    if (ip_proto == 6) {
        uint8_t *tcp_seg = packet + transport_off;
        int tcp_seg_len = (int)(new_pkt_len - (size_t)transport_off);
        tcp_seg[TCP_CKSUM_OFF] = 0;
        tcp_seg[TCP_CKSUM_OFF + 1] = 0;
        uint16_t tcp_cksum = crypto_calc_tcp_checksum(packet + l3_off, ip_hdr_len, tcp_seg, tcp_seg_len);
        tcp_seg[TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
        tcp_seg[TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
    }

    return (int)new_pkt_len;
}

int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17)
        return (int)pkt_len;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    size_t remaining = pkt_len - (size_t)transport_off;

    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return (int)pkt_len;

    int tunnel_off = transport_off + transport_hdr_size;
    
    // DEBUG LOG:
    if (pkt_len > (size_t)(tunnel_off + 13)) {
        printf("[DEBUG-DEC] Checking Tunnel: tunnel_off=%d, magic_at_%d=0x%02X, expected=0x%02X\n",
                tunnel_off, tunnel_off + nonce_size + 1, packet[tunnel_off + nonce_size + 1], L4_TUNNEL_MAGIC);
    }

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size) ||
        !l4_is_tunnel_header(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    uint8_t policy_id, proto_flag;
    uint8_t nonce[16];
    l4_read_tunnel_header(packet + tunnel_off, nonce_size, nonce, &policy_id, &proto_flag);
    (void)policy_id;
    int mode = packet_crypto_get_mode();

    int nonce_len = (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t enc_len = 0;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;
    if (mode == CRYPTO_MODE_GCM) {
        if (total_after_tunnel < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after_tunnel - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } else {
        enc_len = total_after_tunnel;
    }

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int total_overhead = tunnel_hdr_size;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) total_overhead += AES128_GCM_TAG_SIZE;

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key)
            continue;

        uint8_t *work_ptr = packet + enc_off;
        if (k > 0 && has_backup)
            memcpy(work_ptr, backup, enc_len);

        if (mode == CRYPTO_MODE_GCM) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0)
                continue;
        } else if (mode == CRYPTO_MODE_PQC_GCM) {
            int orig_len;
            uint8_t aad[12] __attribute__((aligned(64)));
            memcpy(aad, packet + l3_off + 12, 8);      // Src/Dst IP
            memcpy(aad + 8, packet + transport_off, 4); // Src/Dst Port

            // DEBUG DUMP AAD/NONCE/KEY
            printf("[DEBUG-DEC] AAD: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X\n",
                    aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7], aad[8], aad[9], aad[10], aad[11]);
            printf("[DEBUG-DEC] Nonce: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                    nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5],
                    nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11]);
            printf("[DEBUG-DEC] Key(first 4): %02X%02X%02X%02X (Slot: %d)\n",
                    key[0], key[1], key[2], key[3], k);

            int res = trf_decrypt_payload_gcm(ctx->cipher_ctx_dec, key, nonce, nonce_len, aad, 12, work_ptr, (int)enc_len, &orig_len);
            if (res != TRF_PQC_OK) {
                printf("[DEBUG-DEC] PQC Decrypt FAILED: code=%d, enc_len=%zu\n", res, enc_len);
                continue;
            }
            printf("[DEBUG-DEC] PQC Decrypt SUCCESS: orig_len=%d\n", orig_len);
            enc_len = (size_t)orig_len; 
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0)
                continue;
        }

        memmove(packet + tunnel_off, work_ptr, enc_len);

        uint16_t old_totlen = ((uint16_t)packet[l3_off + 2] << 8) | packet[l3_off + 3];
        uint16_t new_totlen = old_totlen - (uint16_t)total_overhead;
        packet[l3_off + 2] = (uint8_t)(new_totlen >> 8);
        packet[l3_off + 3] = (uint8_t)(new_totlen & 0xFF);
        packet[l3_off + 10] = 0;
        packet[l3_off + 11] = 0;
        uint16_t cksum = crypto_calc_ip_checksum(packet + l3_off, ip_hdr_len);
        packet[l3_off + 10] = (uint8_t)(cksum >> 8);
        packet[l3_off + 11] = (uint8_t)(cksum & 0xFF);

        size_t new_pkt_len = pkt_len - (size_t)total_overhead;
        if (ip_proto == 6) {
            uint8_t *tcp_seg = packet + transport_off;
            int tcp_seg_len = (int)(new_pkt_len - (size_t)transport_off);
            tcp_seg[TCP_CKSUM_OFF] = 0;
            tcp_seg[TCP_CKSUM_OFF + 1] = 0;
            uint16_t tcp_cksum = crypto_calc_tcp_checksum(packet + l3_off, ip_hdr_len, tcp_seg, tcp_seg_len);
            tcp_seg[TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
            tcp_seg[TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
        } else if (ip_proto == 17) {
            uint8_t *udp_seg = packet + transport_off;
            size_t udp_seg_len = new_pkt_len - (size_t)transport_off;
            if (udp_seg_len >= 8) {
                udp_seg[UDP_CKSUM_OFF] = 0;
                udp_seg[UDP_CKSUM_OFF + 1] = 0;
                uint16_t udp_cksum = crypto_calc_udp_checksum(packet + l3_off, ip_hdr_len,
                                                                udp_seg, (int)udp_seg_len);
                udp_seg[UDP_CKSUM_OFF] = (uint8_t)(udp_cksum >> 8);
                udp_seg[UDP_CKSUM_OFF + 1] = (uint8_t)(udp_cksum & 0xFF);
            }
        }

        return (int)new_pkt_len;
    }
    return -1;
}

static void l4_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

int crypto_layer4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *transport_hdr, int transport_hdr_len,
    const uint8_t *app_payload, uint32_t app_payload_len,
    uint16_t pkt_id, uint8_t frag_index, uint32_t tcp_seq_delta,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    if (!ctx || !ctx->initialized || !out_buf || !out_len) return -1;

    uint8_t ip_proto = ip_hdr[9];
    int is_tcp = (ip_proto == 6);

    int mode = packet_crypto_get_mode();
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) total_overhead += AES128_GCM_TAG_SIZE;
    size_t need = (size_t)(14 + ip_hdr_len + transport_hdr_len + total_overhead + app_payload_len);
    if (need > out_max) return -1;

    int offset = 0;
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;
    memcpy(out_buf + offset, transport_hdr, transport_hdr_len);
    offset += transport_hdr_len;

    if (is_tcp && transport_hdr_len >= 20) {
        uint8_t *tcp_out = out_buf + 14 + ip_hdr_len;
        if (frag_index == 0) {
            tcp_out[TCP_FLAGS_OFF] &= ~(TCP_FLAG_PSH | TCP_FLAG_FIN);
        } else {
            uint32_t seq = ((uint32_t)tcp_out[TCP_SEQ_OFF] << 24) |
                           ((uint32_t)tcp_out[TCP_SEQ_OFF + 1] << 16) |
                           ((uint32_t)tcp_out[TCP_SEQ_OFF + 2] << 8) |
                           (uint32_t)tcp_out[TCP_SEQ_OFF + 3];
            seq += tcp_seq_delta;
            tcp_out[TCP_SEQ_OFF]     = (uint8_t)(seq >> 24);
            tcp_out[TCP_SEQ_OFF + 1] = (uint8_t)(seq >> 16);
            tcp_out[TCP_SEQ_OFF + 2] = (uint8_t)(seq >> 8);
            tcp_out[TCP_SEQ_OFF + 3] = (uint8_t)(seq & 0xFF);
        }
    }

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key) return -1;

    int enc_off = offset + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    memcpy(out_buf + enc_off, app_payload, app_payload_len);

    l4_write_tunnel_header_frag(out_buf + offset, nonce, nonce_size);
    l4_write_frag_tag(out_buf + offset + tunnel_hdr_size, pkt_id, frag_index);

    if (mode == CRYPTO_MODE_GCM) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                    out_buf + enc_off, (int)app_payload_len, tag) != 0)
            return -1;
        memcpy(out_buf + enc_off + app_payload_len, tag, AES128_GCM_TAG_SIZE);
    } else if (mode == CRYPTO_MODE_PQC_GCM) {
        int new_len;
        // Prepare AAD for fragment
        uint8_t aad[12];
        memcpy(aad, ip_hdr + 12, 8);
        memcpy(aad + 8, transport_hdr, 4);

        if (trf_encrypt_payload_gcm(ctx->cipher_ctx_enc, key, nonce, nonce_len, aad, 12, out_buf + enc_off, (int)app_payload_len, &new_len) != TRF_PQC_OK)
            return -1;
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)app_payload_len) != 0)
            return -1;
    }

    uint32_t new_totlen = (uint32_t)(ip_hdr_len + transport_hdr_len + total_overhead + app_payload_len);
    out_buf[14 + 2] = (uint8_t)(new_totlen >> 8);
    out_buf[14 + 3] = (uint8_t)(new_totlen & 0xFF);
    out_buf[14 + 10] = 0;
    out_buf[14 + 11] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, ip_hdr_len);
    out_buf[14 + 10] = (uint8_t)(cksum >> 8);
    out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

    *out_len = (uint32_t)(enc_off + app_payload_len);
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) *out_len += AES128_GCM_TAG_SIZE;

    if (is_tcp) {
        int tcp_seg_len = (int)(*out_len - 14 - ip_hdr_len);
        uint8_t *tcp_seg = out_buf + 14 + ip_hdr_len;
        tcp_seg[TCP_CKSUM_OFF] = 0;
        tcp_seg[TCP_CKSUM_OFF + 1] = 0;
        uint16_t tcp_cksum = crypto_calc_tcp_checksum(out_buf + 14, ip_hdr_len, tcp_seg, tcp_seg_len);
        tcp_seg[TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
        tcp_seg[TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
    }
    return 0;
}

static void l4_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index) return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0) return -1;

    if (pkt_len < (size_t)l3_off + 20) return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17) return -1;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;

    int transport_off = l3_off + ip_hdr_len;
    size_t remaining = pkt_len - transport_off;

    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0) return -1;

    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + transport_hdr_size;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return -1;
    if (packet[tunnel_off + nonce_size + 1] != L4_FRAG_MAGIC)
        return -1;

    l4_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);
    int mode = packet_crypto_get_mode();
    int nonce_len = (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    size_t total_after = pkt_len - enc_off;
    size_t enc_len = 0;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (mode == CRYPTO_MODE_GCM) {
        if (total_after < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } else {
        enc_len = total_after;
    }

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup) memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) total_overhead += AES128_GCM_TAG_SIZE;

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        uint8_t *work = packet + enc_off;
        if (k > 0 && has_backup) memcpy(work, backup, enc_len);

        if (mode == CRYPTO_MODE_GCM) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work, (int)enc_len, tag) != 0)
                continue;
        } else if (mode == CRYPTO_MODE_PQC_GCM) {
            int orig_len;
            uint8_t aad[12] __attribute__((aligned(64)));
            memcpy(aad, packet + l3_off + 12, 8);
            memcpy(aad + 8, packet + transport_off, 4);

            if (trf_decrypt_payload_gcm(ctx->cipher_ctx_dec, key, nonce, nonce_len, aad, 12, work, (int)enc_len, &orig_len) != TRF_PQC_OK)
                continue;
            enc_len = (size_t)orig_len;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
                continue;
        }

        memmove(packet + tunnel_off, packet + enc_off, enc_len);

        uint16_t old_totlen = ((uint16_t)packet[l3_off + 2] << 8) | packet[l3_off + 3];
        uint16_t new_totlen = old_totlen - (uint16_t)total_overhead;
        packet[l3_off + 2] = (uint8_t)(new_totlen >> 8);
        packet[l3_off + 3] = (uint8_t)(new_totlen & 0xFF);
        packet[l3_off + 10] = 0;
        packet[l3_off + 11] = 0;
        uint16_t cksum = crypto_calc_ip_checksum(packet + l3_off, ip_hdr_len);
        packet[l3_off + 10] = (uint8_t)(cksum >> 8);
        packet[l3_off + 11] = (uint8_t)(cksum & 0xFF);

        size_t new_pkt_len = pkt_len - (size_t)total_overhead;
        if (ip_proto == 6) {
            uint8_t *tcp_seg = packet + transport_off;
            size_t tcp_seg_len = new_pkt_len - (size_t)transport_off;
            if (tcp_seg_len >= 20) {
                tcp_seg[TCP_CKSUM_OFF] = 0;
                tcp_seg[TCP_CKSUM_OFF + 1] = 0;
                uint16_t tcp_cksum = crypto_calc_tcp_checksum(packet + l3_off,
                                                              ip_hdr_len,
                                                              tcp_seg,
                                                              (int)tcp_seg_len);
                tcp_seg[TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
                tcp_seg[TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
            }
        } else if (ip_proto == 17) {
            uint8_t *udp_seg = packet + transport_off;
            size_t udp_seg_len = new_pkt_len - (size_t)transport_off;
            if (udp_seg_len >= 8) {
                udp_seg[UDP_CKSUM_OFF] = 0;
                udp_seg[UDP_CKSUM_OFF + 1] = 0;
                uint16_t udp_cksum = crypto_calc_udp_checksum(packet + l3_off,
                                                                ip_hdr_len,
                                                                udp_seg, (int)udp_seg_len);
                udp_seg[UDP_CKSUM_OFF] = (uint8_t)(udp_cksum >> 8);
                udp_seg[UDP_CKSUM_OFF + 1] = (uint8_t)(udp_cksum & 0xFF);
            }
        }

        return (int)(pkt_len - total_overhead);
    }
    return -1;
}
