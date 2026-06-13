#define _POSIX_C_SOURCE 199309L
#include "../../inc/fragment.h"
#include "../../inc/packet_crypto.h"
#include "../../inc/crypto_layer2.h"
#include "../../inc/crypto_layer3.h"
#include "../../inc/crypto_layer4.h"
#include "../../inc/config.h"
#include "../../sig_encrypt/inc/traffic_crypto.h"
#include "../../sig_encrypt/inc/pqc_handshake.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#define L4_FRAG_MAGIC  (0xA5 | FRAG_FLAG_BIT)

static atomic_uint_fast32_t g_pkt_id_counter = 0;

uint16_t frag_next_pkt_id(void) {
    return (uint16_t)(atomic_fetch_add(&g_pkt_id_counter, 1) & 0xFFFF);
}

void frag_table_init(struct frag_table *ft) {
    memset(ft, 0, sizeof(*ft));
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void frag_table_gc(struct frag_table *ft) {
    uint64_t now = get_time_ns();
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        if (ft->entries[i].valid &&
            (now - ft->entries[i].timestamp_ns) > FRAG_TIMEOUT_NS) {
            ft->entries[i].valid = 0;
        }
    }
}

static void frag_write_hdr(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
}

static void frag_read_hdr(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index) {
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int nonce_size = packet_crypto_get_nonce_size();

    if (pkt_len < (uint32_t)(14 + 20 + tunnel_hdr_size + FRAG_HDR_SIZE))
        return 0;

    uint8_t ip_proto = pkt_data[14 + 9];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (ip_proto != fake_proto)
        return 0;

    int tunnel_off = 14 + 20;
    uint8_t orig_proto_byte = pkt_data[tunnel_off + nonce_size];

    if (!(orig_proto_byte & FRAG_FLAG_BIT))
        return 0;

    frag_read_hdr(pkt_data + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);
    return 1;
}

static int build_and_encrypt_fragment(struct packet_crypto_ctx *ctx,
                                       const uint8_t *eth_hdr,
                                       const uint8_t *ip_hdr,
                                       int ip_hdr_len,
                                       const uint8_t *payload,
                                       uint32_t payload_len,
                                       uint8_t orig_proto,
                                       uint16_t pkt_id,
                                       uint8_t frag_index,
                                       uint8_t *out_buf,
                                       uint32_t *out_len) {
    int offset = 0;
    int mode = packet_crypto_get_mode();
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    memcpy(out_buf, eth_hdr, 14);
    offset += 14;

    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;

    memcpy(out_buf + offset, payload, payload_len);
    offset += payload_len;

    uint16_t ip_total = (uint16_t)(ip_hdr_len + payload_len);
    out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
    out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

    out_buf[14 + 9] = orig_proto;

    out_buf[14 + 10] = 0;
    out_buf[14 + 11] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, ip_hdr_len);
    out_buf[14 + 10] = (uint8_t)(cksum >> 8);
    out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

    uint32_t pkt_len = (uint32_t)offset;

    packet_crypto_update_keys(ctx);

    uint16_t ether_type = ((uint16_t)out_buf[12] << 8) | out_buf[13];
    uint8_t proto_flag;
    int tunnel_off;

    if (ether_type == 0x0800) {
        proto_flag = PROTO_FLAG_IPV4;
        tunnel_off = 14 + ip_hdr_len;
    } else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
        tunnel_off = 14 + 40;
    } else {
        return -1;
    }

    size_t transport_len = pkt_len - tunnel_off;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    memmove(out_buf + tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE,
            out_buf + tunnel_off,
            transport_len);

    uint8_t flagged_proto = orig_proto | FRAG_FLAG_BIT;
    crypto_write_l3_tunnel_header(out_buf + tunnel_off, nonce, nonce_size,
                                  0, flagged_proto);

    frag_write_hdr(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (proto_flag == PROTO_FLAG_IPV4) {
        out_buf[14 + 9] = fake_proto;
    } 
    
    else {
        out_buf[14 + 6] = fake_proto;
    }

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key) return -1;

    int hdr_overhead = tunnel_hdr_size + FRAG_HDR_SIZE;

    if (mode == CRYPTO_MODE_GCM) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                    out_buf + enc_off, (int)transport_len, tag) != 0) {
            return -1;
        }
        memcpy(out_buf + enc_off + transport_len, tag, AES128_GCM_TAG_SIZE);
        hdr_overhead += AES128_GCM_TAG_SIZE;
    } else if (mode == CRYPTO_MODE_PQC_GCM) {
        // int new_len;
        // Prepare AAD for fragment (IP Src/Dst)
        uint8_t aad[8];
        memcpy(aad, out_buf + 14 + 12, 8); 

        // if (trf_encrypt_payload_gcm(key, nonce, nonce_len, aad, 8,
        //                             out_buf + enc_off, (int)transport_len, &new_len) != TRF_PQC_OK)
        //     return -1;
        hdr_overhead += AES128_GCM_TAG_SIZE;
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv,
                                     out_buf + enc_off,
                                     (int)transport_len) != 0) {
            return -1;
        }
    }

    if (proto_flag == PROTO_FLAG_IPV4) {
        uint16_t old_totlen = ((uint16_t)out_buf[14 + 2] << 8) | out_buf[14 + 3];
        uint16_t new_totlen = old_totlen + (uint16_t)hdr_overhead;
        out_buf[14 + 2] = (uint8_t)(new_totlen >> 8);
        out_buf[14 + 3] = (uint8_t)(new_totlen & 0xFF);

        out_buf[14 + 10] = 0;
        out_buf[14 + 11] = 0;
        cksum = crypto_calc_ip_checksum(out_buf + 14, ip_hdr_len);
        out_buf[14 + 10] = (uint8_t)(cksum >> 8);
        out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);
    } 
    
    else {
        uint16_t old_paylen = ((uint16_t)out_buf[14 + 4] << 8) | out_buf[14 + 5];
        uint16_t new_paylen = old_paylen + (uint16_t)hdr_overhead;
        out_buf[14 + 4] = (uint8_t)(new_paylen >> 8);
        out_buf[14 + 5] = (uint8_t)(new_paylen & 0xFF);
    }

    *out_len = pkt_len + (uint32_t)hdr_overhead;
    if (ctx) {
        sig_pqc_record_sent(ctx->policy_id);
    }
    return 0;
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint8_t *frag1, uint32_t *frag1_len,
                           uint8_t *frag2, uint32_t *frag2_len) {
    if (pkt_len < 14 + 20)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + 14;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;

    if (ether_type == 0x0800) {
        ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20) return -1;
    } 
    
    else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } 
    
    else {
        return -1;
    }

    if (pkt_len < (uint32_t)(14 + ip_hdr_len))
        return -1;

    uint8_t orig_proto;
    if (ether_type == 0x0800) {
        orig_proto = ip_hdr[9];
    } 
    
    else {
        orig_proto = ip_hdr[6];
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    uint32_t half1 = payload_len / 2;
    uint32_t half2 = payload_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    if (build_and_encrypt_fragment(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                    payload, half1, orig_proto,
                                    pkt_id, 0,
                                    frag1, frag1_len) != 0) {
        return -1;
    }

    if (build_and_encrypt_fragment(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                    payload + half1, half2, orig_proto,
                                    pkt_id, 1,
                                    frag2, frag2_len) != 0) {
        return -1;
    }

    return 0;
}

int frag_decrypt_fragment(struct packet_crypto_ctx *ctx,
                          uint8_t *packet, size_t pkt_len,
                          uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    if (pkt_len < (size_t)(14 + 20 + tunnel_hdr_size + FRAG_HDR_SIZE))
        return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    uint8_t proto_flag;
    int tunnel_off;
    int ip_hdr_len;
    int mode = packet_crypto_get_mode();

    if (ether_type == 0x0800) {
        if (packet[14 + 9] != fake_proto) return -1;
        proto_flag = PROTO_FLAG_IPV4;
        ip_hdr_len = (packet[14] & 0x0F) * 4;
        tunnel_off = 14 + ip_hdr_len;
    } 
    
    else if (ether_type == 0x86DD) {
        if (packet[14 + 6] != fake_proto) return -1;
        proto_flag = PROTO_FLAG_IPV6;
        ip_hdr_len = 40;
        tunnel_off = 14 + 40;
    } 
    
    else {
        return -1;
    }

    uint8_t rd_proto_flag, orig_proto_raw;
    uint8_t nonce[16];
    crypto_read_l3_tunnel_header(packet + tunnel_off, nonce_size,
                                  nonce, &rd_proto_flag, NULL, &orig_proto_raw);

    uint8_t orig_proto = orig_proto_raw & ~FRAG_FLAG_BIT;

    frag_read_hdr(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    int nonce_len = (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM)
                    ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE;
    size_t total_after_hdr = pkt_len - enc_off;

    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    // uint8_t hmac_tag[32];
    if (mode == CRYPTO_MODE_GCM) {
        if (total_after_hdr < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after_hdr - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } else {
        enc_len = total_after_hdr;
    }

    uint8_t backup[2048];
    int has_backup = 0;
    if (enc_len <= sizeof(backup)) {
        memcpy(backup, packet + enc_off, enc_len);
        has_backup = 1;
    }

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int hdr_overhead = tunnel_hdr_size + FRAG_HDR_SIZE;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC_GCM) hdr_overhead += AES128_GCM_TAG_SIZE;

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        if (k > 0 && has_backup) {
            memcpy(packet + enc_off, backup, enc_len);
        }

        if (mode == CRYPTO_MODE_GCM) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len,
                                        packet + enc_off, (int)enc_len, tag) != 0) {
                continue;
            }
        } else if (mode == CRYPTO_MODE_PQC_GCM) {
            int orig_len;
            // Prepare AAD for fragment decryption
            uint8_t aad[8];
            memcpy(aad, packet + 14 + 12, 8);

            // if (trf_decrypt_payload_gcm(key, nonce, nonce_len, aad, 8, packet + enc_off, (int)enc_len, &orig_len) != TRF_PQC_OK)
            //     continue;
            enc_len = orig_len;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)enc_len) != 0)
                continue;

            if (*out_frag_index == 0 && (orig_proto == 6 || orig_proto == 17)) {
                if (enc_len >= 4) {
                    uint16_t src_port = ((uint16_t)packet[enc_off] << 8) | packet[enc_off + 1];
                    uint16_t dst_port = ((uint16_t)packet[enc_off + 2] << 8) | packet[enc_off + 3];
                    if (src_port == 0 && dst_port == 0)
                        continue;
                }
            }
        }

        if (key_order[k] == KEY_SLOT_CURRENT && ctx->key_slots_valid[KEY_SLOT_PREV]) {
            ctx->key_slots_valid[KEY_SLOT_PREV] = false;
            sig_pqc_discard_prev_key(ctx->policy_id);
        }

        if (key_order[k] == KEY_SLOT_NEXT) {
            memcpy(ctx->keys[KEY_SLOT_PREV], ctx->keys[KEY_SLOT_CURRENT], AES_MAX_KEY_SIZE);
            ctx->key_ids[KEY_SLOT_PREV] = ctx->key_ids[KEY_SLOT_CURRENT];
            ctx->key_slots_valid[KEY_SLOT_PREV] = ctx->key_slots_valid[KEY_SLOT_CURRENT];

            memcpy(ctx->keys[KEY_SLOT_CURRENT], ctx->keys[KEY_SLOT_NEXT], AES_MAX_KEY_SIZE);
            ctx->key_ids[KEY_SLOT_CURRENT] = ctx->key_ids[KEY_SLOT_NEXT];
            ctx->key_slots_valid[KEY_SLOT_CURRENT] = true;

            ctx->key_slots_valid[KEY_SLOT_NEXT] = false;
            printf("[PQC-DATA] Fragment L3 Implicit key promotion: NEXT -> CURRENT for Policy %d!\n", ctx->policy_id);
            sig_pqc_promote_responder_key(ctx->policy_id);
        }

        memmove(packet + tunnel_off, packet + enc_off, enc_len);

        if (proto_flag == PROTO_FLAG_IPV4) {
            packet[14 + 9] = orig_proto;
            uint16_t old_totlen = ((uint16_t)packet[14 + 2] << 8) | packet[14 + 3];
            uint16_t new_totlen = old_totlen - (uint16_t)hdr_overhead;
            packet[14 + 2] = (uint8_t)(new_totlen >> 8);
            packet[14 + 3] = (uint8_t)(new_totlen & 0xFF);

            packet[14 + 10] = 0;
            packet[14 + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(packet + 14, ip_hdr_len);
            packet[14 + 10] = (uint8_t)(cksum >> 8);
            packet[14 + 11] = (uint8_t)(cksum & 0xFF);
        }
        
        else {
            packet[14 + 6] = orig_proto;
            uint16_t old_paylen = ((uint16_t)packet[14 + 4] << 8) | packet[14 + 5];
            uint16_t new_paylen = old_paylen - (uint16_t)hdr_overhead;
            packet[14 + 4] = (uint8_t)(new_paylen >> 8);
            packet[14 + 5] = (uint8_t)(new_paylen & 0xFF);
        }

        if (ctx) {
            sig_pqc_record_recv(ctx->policy_id);
        }
        return (int)(pkt_len - hdr_overhead);
    }

    return -1;
}

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len) {
    if (pkt_len < 14 + 20)
        return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;
    if (ether_type == 0x0800) {
        ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    } 
    
    else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } 
    
    else {
        return -1;
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    if (frag_index == 0) {
        entry->pkt_id = pkt_id;
        entry->data_len = payload_len;
        if (payload_len > sizeof(entry->data)) {
            return -1;
        }
        memcpy(entry->data, payload, payload_len);
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, pkt_data + 14, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        entry->orig_proto = pkt_data[14 + 9];
        entry->timestamp_ns = now;
        entry->valid = 1;
        return 0;
    }

    if (frag_index == 1) {
        if (!entry->valid || entry->pkt_id != pkt_id) {
            return -1;
        }

        if ((now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
            entry->valid = 0;
            return -1;
        }

        uint32_t total_payload = entry->data_len + payload_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + total_payload;

        if (total_pkt > 4096) {
            entry->valid = 0;
            return -1;
        }

        int off = 0;

        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;

        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;

        memcpy(out_buf + off, entry->data, entry->data_len);
        off += entry->data_len;

        memcpy(out_buf + off, payload, payload_len);
        off += payload_len;

        if (ether_type == 0x0800) {
            uint16_t ip_total = (uint16_t)(entry->ip_hdr_len + total_payload);
            out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
            out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

            out_buf[14 + 10] = 0;
            out_buf[14 + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, entry->ip_hdr_len);
            out_buf[14 + 10] = (uint8_t)(cksum >> 8);
            out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

            if (entry->orig_proto == 6 && total_payload >= 20) {
                uint8_t *tcp_seg = out_buf + 14 + entry->ip_hdr_len;
                int tcp_seg_len = (int)total_payload;
                tcp_seg[16] = 0;
                tcp_seg[17] = 0;
                uint16_t tcp_cksum = crypto_calc_tcp_checksum(out_buf + 14,
                                                               entry->ip_hdr_len,
                                                               tcp_seg,
                                                               tcp_seg_len);
                tcp_seg[16] = (uint8_t)(tcp_cksum >> 8);
                tcp_seg[17] = (uint8_t)(tcp_cksum & 0xFF);
            } else if (entry->orig_proto == 17 && total_payload >= 8) {
                uint8_t *udp_seg = out_buf + 14 + entry->ip_hdr_len;
                uint16_t old_udp_ck = ((uint16_t)udp_seg[6] << 8) | udp_seg[7];
                if (old_udp_ck != 0) {
                    udp_seg[6] = 0;
                    udp_seg[7] = 0;
                    uint16_t udp_cksum = crypto_calc_udp_checksum(out_buf + 14,
                                                                    entry->ip_hdr_len,
                                                                    udp_seg,
                                                                    (int)total_payload);
                    udp_seg[6] = (uint8_t)(udp_cksum >> 8);
                    udp_seg[7] = (uint8_t)(udp_cksum & 0xFF);
                }
            }
        } 
        
        else {
            uint16_t ipv6_paylen = (uint16_t)total_payload;
            out_buf[14 + 4] = (uint8_t)(ipv6_paylen >> 8);
            out_buf[14 + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        *out_len = (uint32_t)off;
        entry->valid = 0;
        return 1;
    }

    return -1;
}

int frag_split_and_encrypt_l2(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len) {
    if (pkt_len < 14 + 20)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + 14;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;

    if (ether_type == 0x0800) {
        ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20) return -1;
    } else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } else {
        return -1;
    }

    if (pkt_len < (uint32_t)(14 + ip_hdr_len))
        return -1;

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    uint32_t half1 = payload_len / 2;
    uint32_t half2 = payload_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    {
        uint32_t off = 0;
        memcpy(frag1, eth_hdr, 14);
        off += 14;

        frag_write_hdr(frag1 + off, pkt_id, 0);
        off += FRAG_HDR_SIZE;

        memcpy(frag1 + off, ip_hdr, ip_hdr_len);
        off += ip_hdr_len;

        memcpy(frag1 + off, payload, half1);
        off += half1;

        if (ether_type == 0x0800) {
            uint16_t ip_total = (uint16_t)(ip_hdr_len + half1);
            frag1[14 + FRAG_HDR_SIZE + 2] = (uint8_t)(ip_total >> 8);
            frag1[14 + FRAG_HDR_SIZE + 3] = (uint8_t)(ip_total & 0xFF);

            frag1[14 + FRAG_HDR_SIZE + 10] = 0;
            frag1[14 + FRAG_HDR_SIZE + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(frag1 + 14 + FRAG_HDR_SIZE, ip_hdr_len);
            frag1[14 + FRAG_HDR_SIZE + 10] = (uint8_t)(cksum >> 8);
            frag1[14 + FRAG_HDR_SIZE + 11] = (uint8_t)(cksum & 0xFF);
        } else {
            uint16_t ipv6_paylen = (uint16_t)half1;
            frag1[14 + FRAG_HDR_SIZE + 4] = (uint8_t)(ipv6_paylen >> 8);
            frag1[14 + FRAG_HDR_SIZE + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        int enc_len = crypto_layer2_encrypt(ctx, frag1, off);
        if (enc_len < 0) return -1;
        *frag1_len = (uint32_t)enc_len;
    }

    {
        uint32_t off = 0;
        memcpy(frag2, eth_hdr, 14);
        off += 14;

        frag_write_hdr(frag2 + off, pkt_id, 1);
        off += FRAG_HDR_SIZE;

        memcpy(frag2 + off, payload + half1, half2);
        off += half2;

        int enc_len = crypto_layer2_encrypt(ctx, frag2, off);
        if (enc_len < 0) return -1;
        *frag2_len = (uint32_t)enc_len;
    }

    return 0;
}

int frag_is_fragment_l2(const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index) {
    if (pkt_len < 14 + FRAG_HDR_SIZE + 1)
        return 0;

    uint8_t first_byte = pkt_data[14] >> 4;
    if (first_byte == 4 || first_byte == 6)
        return 0;

    frag_read_hdr(pkt_data + 14, pkt_id, frag_index);

    if (*frag_index == 0) {
        if (pkt_len < 14 + FRAG_HDR_SIZE + 20)
            return 0;
        uint8_t inner_ver = pkt_data[14 + FRAG_HDR_SIZE] >> 4;
        if (!(inner_ver == 4 || inner_ver == 6))
            return 0;
    }

    return 1;
}

int frag_try_reassemble_l2(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len) {
    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    if (frag_index == 0) {
        if (pkt_len < 14 + FRAG_HDR_SIZE + 20)
            return -1;

        const uint8_t *ip_hdr = pkt_data + 14 + FRAG_HDR_SIZE;
        int ip_hdr_len;
        if (ether_type == 0x0800) {
            ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
            if (ip_hdr_len < 20) return -1;
        } else if (ether_type == 0x86DD) {
            ip_hdr_len = 40;
        } else {
            return -1;
        }

        const uint8_t *payload = pkt_data + 14 + FRAG_HDR_SIZE + ip_hdr_len;
        uint32_t payload_len = pkt_len - (14 + FRAG_HDR_SIZE + ip_hdr_len);

        entry->pkt_id = pkt_id;
        entry->data_len = payload_len;
        if (payload_len > sizeof(entry->data))
            return -1;
        memcpy(entry->data, payload, payload_len);
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, ip_hdr, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        entry->orig_proto = (ether_type == 0x0800) ? ip_hdr[9] : ip_hdr[6];
        entry->timestamp_ns = now;
        entry->valid = 1;
        return 0;
    }

    if (frag_index == 1) {
        if (pkt_len < 14 + FRAG_HDR_SIZE + 1)
            return -1;

        if (!entry->valid || entry->pkt_id != pkt_id)
            return -1;

        if ((now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
            entry->valid = 0;
            return -1;
        }

        const uint8_t *payload = pkt_data + 14 + FRAG_HDR_SIZE;
        uint32_t payload_len = pkt_len - (14 + FRAG_HDR_SIZE);

        uint32_t total_payload = entry->data_len + payload_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + total_payload;
        if (total_pkt > 4096) {
            entry->valid = 0;
            return -1;
        }

        int off = 0;
        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;

        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;

        memcpy(out_buf + off, entry->data, entry->data_len);
        off += entry->data_len;

        memcpy(out_buf + off, payload, payload_len);
        off += payload_len;

        uint16_t orig_etype = ((uint16_t)entry->eth_hdr[12] << 8) | entry->eth_hdr[13];
        if (orig_etype == 0x0800) {
            uint16_t ip_total = (uint16_t)(entry->ip_hdr_len + total_payload);
            out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
            out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

            out_buf[14 + 10] = 0;
            out_buf[14 + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, entry->ip_hdr_len);
            out_buf[14 + 10] = (uint8_t)(cksum >> 8);
            out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);
        } else {
            uint16_t ipv6_paylen = (uint16_t)total_payload;
            out_buf[14 + 4] = (uint8_t)(ipv6_paylen >> 8);
            out_buf[14 + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        *out_len = (uint32_t)off;
        entry->valid = 0;
        return 1;
    }

    return -1;
}

static void frag_read_hdr_l4(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int frag_split_and_encrypt_l4(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len) {
    if (pkt_len < 14 + 20 + 8) return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return -1;

    uint8_t ip_proto = pkt_data[14 + 9];
    if (ip_proto != 6 && ip_proto != 17) return -1;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;

    int transport_off = 14 + ip_hdr_len;
    size_t remaining = pkt_len - transport_off;
    int transport_hdr_len = crypto_layer4_get_transport_hdr_size(
        pkt_data + transport_off, ip_proto, remaining);
    if (transport_hdr_len < 0) return -1;

    int app_off = transport_off + transport_hdr_len;
    uint32_t app_len = pkt_len - app_off;
    if (app_len == 0) return -1;

    uint32_t half1 = app_len / 2;
    uint32_t half2 = app_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + 14;
    const uint8_t *transport_hdr = pkt_data + transport_off;

    if (crypto_layer4_encrypt_fragment_single(ctx,
            eth_hdr, ip_hdr, ip_hdr_len,
            transport_hdr, transport_hdr_len,
            pkt_data + app_off, half1,
            pkt_id, 0, 0,
            frag1, 2048, frag1_len) != 0) {
        return -1;
    }
    if (crypto_layer4_encrypt_fragment_single(ctx,
            eth_hdr, ip_hdr, ip_hdr_len,
            transport_hdr, transport_hdr_len,
            pkt_data + app_off + half1, half2,
            pkt_id, 1, half1,
            frag2, 2048, frag2_len) != 0) {
        return -1;
    }
    return 0;
}

int frag_is_fragment_l4(const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index) {
    if (pkt_len < 14 + 20 + 8) return 0;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return 0;

    uint8_t ip_proto = pkt_data[14 + 9];
    if (ip_proto != 6 && ip_proto != 17) return 0;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20) return 0;

    int transport_off = 14 + ip_hdr_len;
    size_t remaining = pkt_len - transport_off;
    int transport_hdr_len = crypto_layer4_get_transport_hdr_size(
        pkt_data + transport_off, ip_proto, remaining);
    if (transport_hdr_len < 0) return 0;

    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + transport_hdr_len;

    if (pkt_len < (uint32_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return 0;

    if (pkt_data[tunnel_off + nonce_size] != L4_FRAG_MAGIC)
        return 0;

    frag_read_hdr_l4(pkt_data + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);
    return 1;
}

int frag_decrypt_fragment_l4(struct packet_crypto_ctx *ctx,
                             uint8_t *packet, size_t pkt_len,
                             uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    return crypto_layer4_decrypt_fragment(ctx, packet, pkt_len, out_pkt_id, out_frag_index);
}

int frag_try_reassemble_l4(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len) {
    if (pkt_len < 14 + 20) return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return -1;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    if (frag_index == 0) {
        int transport_hdr_len = crypto_layer4_get_transport_hdr_size(
            (const uint8_t *)payload, pkt_data[14 + 9], payload_len);
        if (transport_hdr_len < 0) return -1;

        entry->pkt_id = pkt_id;
        entry->data_len = payload_len;
        entry->transport_hdr_len = (uint16_t)transport_hdr_len;
        if (payload_len > sizeof(entry->data)) return -1;
        memcpy(entry->data, payload, payload_len);
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, pkt_data + 14, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        entry->orig_proto = pkt_data[14 + 9];
        entry->timestamp_ns = now;
        entry->valid = 1;
        return 0;
    }

    if (frag_index == 1) {
        if (!entry->valid || entry->pkt_id != pkt_id) return -1;
        if ((now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
            entry->valid = 0;
            return -1;
        }

        uint32_t first_half_len = entry->data_len - entry->transport_hdr_len;
        uint32_t second_half_len = payload_len - entry->transport_hdr_len;
        uint32_t total_app = first_half_len + second_half_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + entry->transport_hdr_len + total_app;

        if (total_pkt > 4096) {
            entry->valid = 0;
            return -1;
        }

        int off = 0;
        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;
        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;
        memcpy(out_buf + off, entry->data, entry->data_len);
        off += entry->data_len;
        memcpy(out_buf + off, payload + entry->transport_hdr_len, second_half_len);
        off += second_half_len;

        uint16_t ip_total = (uint16_t)(entry->ip_hdr_len + entry->transport_hdr_len + total_app);
        out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
        out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);
        out_buf[14 + 10] = 0;
        out_buf[14 + 11] = 0;
        uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, entry->ip_hdr_len);
        out_buf[14 + 10] = (uint8_t)(cksum >> 8);
        out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

        if (entry->orig_proto == 6 && entry->transport_hdr_len >= 20) {
            uint8_t *tcp_out = out_buf + 14 + entry->ip_hdr_len;
            const uint8_t *tcp_second = payload;
            tcp_out[13] = tcp_second[13];
            tcp_out[16] = 0;
            tcp_out[17] = 0;
            int tcp_seg_len = (int)(off - 14 - entry->ip_hdr_len);
            uint16_t tcp_cksum = crypto_calc_tcp_checksum(out_buf + 14, entry->ip_hdr_len,
                                                          tcp_out, tcp_seg_len);
            tcp_out[16] = (uint8_t)(tcp_cksum >> 8);
            tcp_out[17] = (uint8_t)(tcp_cksum & 0xFF);
        } else if (entry->orig_proto == 17 && entry->transport_hdr_len >= 8) {
            uint8_t *udp_out = out_buf + 14 + entry->ip_hdr_len;
            int udp_seg_len = (int)(off - 14 - entry->ip_hdr_len);
            udp_out[6] = 0;
            udp_out[7] = 0;
            uint16_t udp_cksum = crypto_calc_udp_checksum(out_buf + 14, entry->ip_hdr_len,
                                                            udp_out, udp_seg_len);
            udp_out[6] = (uint8_t)(udp_cksum >> 8);
            udp_out[7] = (uint8_t)(udp_cksum & 0xFF);
        }

        *out_len = (uint32_t)off;
        entry->valid = 0;
        return 1;
    }

    return -1;
}
