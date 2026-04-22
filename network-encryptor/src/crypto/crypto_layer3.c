#include "../../inc/crypto_layer3.h"
#include "../../inc/config.h"
#include <string.h>
#include <stdio.h>

#define MIN_ETH_PKT       (ETH_HEADER_SIZE + 8)
#define IPV4_HDR_SIZE      20
#define IPV6_HDR_SIZE      40

#define IPV4_PROTO_OFF     (ETH_HEADER_SIZE + 9)
#define IPV4_TOTLEN_OFF    (ETH_HEADER_SIZE + 2)
#define IPV4_CKSUM_OFF     (ETH_HEADER_SIZE + 10)
#define IPV4_SRC_OFFSET    (ETH_HEADER_SIZE + 12)
#define IPV4_DST_OFFSET    (ETH_HEADER_SIZE + 16)
#define IPV4_ADDR_LEN      4

#define TCP_CKSUM_OFF       16
#define UDP_CKSUM_OFF       6

#define IPV6_NEXTHDR_OFF   (ETH_HEADER_SIZE + 6)
#define IPV6_PAYLEN_OFF    (ETH_HEADER_SIZE + 4)
#define IPV6_SRC_OFFSET    (ETH_HEADER_SIZE + 8)
#define IPV6_DST_OFFSET    (ETH_HEADER_SIZE + 24)
#define IPV6_ADDR_LEN      16

#define IPV4_TUNNEL_OFF    (ETH_HEADER_SIZE + IPV4_HDR_SIZE)
#define IPV6_TUNNEL_OFF    (ETH_HEADER_SIZE + IPV6_HDR_SIZE)

static int verify_decrypted_payload(const uint8_t *payload, size_t len, uint8_t orig_proto) {
    if (orig_proto == 6 || orig_proto == 17) {
        if (len < 4) return 0;
        uint16_t src_port = ((uint16_t)payload[0] << 8) | payload[1];
        uint16_t dst_port = ((uint16_t)payload[2] << 8) | payload[3];
        if (src_port == 0 && dst_port == 0) return 0;
        return 1;
    }
    return 1;
}

int crypto_layer3_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT) return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t proto_flag, orig_proto;
    int tunnel_off;
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    if (ether_type == 0x0800) {
        if (pkt_len < ETH_HEADER_SIZE + IPV4_HDR_SIZE) return -1;
        proto_flag = PROTO_FLAG_IPV4;
        orig_proto = packet[IPV4_PROTO_OFF];
        tunnel_off = IPV4_TUNNEL_OFF;
    } 
    
    else if (ether_type == 0x86DD) {
        if (pkt_len < ETH_HEADER_SIZE + IPV6_HDR_SIZE) return -1;
        proto_flag = PROTO_FLAG_IPV6;
        orig_proto = packet[IPV6_NEXTHDR_OFF];
        tunnel_off = IPV6_TUNNEL_OFF;
    } 
    
    else return (int)pkt_len;

    size_t payload_len = pkt_len - tunnel_off;
    uint32_t counter = packet_crypto_next_counter();

    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + tunnel_off, (int)payload_len, tag) != 0) return -1;
        memmove(packet + tunnel_off + tunnel_hdr_size, packet + tunnel_off, payload_len);
        memcpy(packet + tunnel_off + tunnel_hdr_size + payload_len, tag, AES128_GCM_TAG_SIZE);
    } 
    
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + tunnel_off, (int)payload_len) != 0) return -1;
        memmove(packet + tunnel_off + tunnel_hdr_size, packet + tunnel_off, payload_len);
    }

    crypto_write_l3_tunnel_header(packet + tunnel_off, nonce, nonce_size,
                                  packet_crypto_get_policy_id(), orig_proto);
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (proto_flag == PROTO_FLAG_IPV4) packet[IPV4_PROTO_OFF] = fake_proto;
    else packet[IPV6_NEXTHDR_OFF] = fake_proto;

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES128_GCM_TAG_SIZE : 0);
    if (proto_flag == PROTO_FLAG_IPV4) {
        uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
        uint16_t new_totlen = old_totlen + (uint16_t)total_overhead;
        packet[IPV4_TOTLEN_OFF] = (uint8_t)(new_totlen >> 8);
        packet[IPV4_TOTLEN_OFF + 1] = (uint8_t)(new_totlen & 0xFF);
        packet[IPV4_CKSUM_OFF] = 0; packet[IPV4_CKSUM_OFF + 1] = 0;
        uint16_t cksum = crypto_calc_ip_checksum(packet + ETH_HEADER_SIZE, IPV4_HDR_SIZE);
        packet[IPV4_CKSUM_OFF] = (uint8_t)(cksum >> 8);
        packet[IPV4_CKSUM_OFF + 1] = (uint8_t)(cksum & 0xFF);
    } 
    
    else {
        uint16_t old_paylen = ((uint16_t)packet[IPV6_PAYLEN_OFF] << 8) | packet[IPV6_PAYLEN_OFF + 1];
        uint16_t new_paylen = old_paylen + (uint16_t)total_overhead;
        packet[IPV6_PAYLEN_OFF] = (uint8_t)(new_paylen >> 8);
        packet[IPV6_PAYLEN_OFF + 1] = (uint8_t)(new_paylen & 0xFF);
    }

    return (int)(pkt_len + total_overhead);
}

int crypto_layer3_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT) return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    uint8_t proto_flag;
    int tunnel_off;
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    if (ether_type == 0x0800) {
        if (pkt_len < (size_t)(ETH_HEADER_SIZE + IPV4_HDR_SIZE + tunnel_hdr_size)) return (int)pkt_len;
        if (packet[IPV4_PROTO_OFF] != fake_proto) return (int)pkt_len;
        proto_flag = PROTO_FLAG_IPV4;
        tunnel_off = IPV4_TUNNEL_OFF;
    } 
    
    else if (ether_type == 0x86DD) {
        if (pkt_len < (size_t)(ETH_HEADER_SIZE + IPV6_HDR_SIZE + tunnel_hdr_size)) return (int)pkt_len;
        if (packet[IPV6_NEXTHDR_OFF] != fake_proto) return (int)pkt_len;
        proto_flag = PROTO_FLAG_IPV6;
        tunnel_off = IPV6_TUNNEL_OFF;
    } 
    
    else return (int)pkt_len;

    uint8_t rd_proto_flag, orig_proto;
    uint8_t nonce[16];
    crypto_read_l3_tunnel_header(packet + tunnel_off, nonce_size,
                                  nonce, &rd_proto_flag, NULL, &orig_proto);

    if (proto_flag == PROTO_FLAG_IPV4)
        packet[IPV4_PROTO_OFF] = orig_proto;
    else
        packet[IPV6_NEXTHDR_OFF] = orig_proto;

    int nonce_len;
    if (is_gcm) {
        nonce_len = nonce_size;
    } 
    
    else {
        nonce_len = AES128_IV_SIZE;
    }

    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t total_after_tunnel = pkt_len - enc_off;
    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after_tunnel < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after_tunnel - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } 
    
    else enc_len = total_after_tunnel;

    uint8_t backup[2048];
    int has_backup = 0;
    if (enc_len <= sizeof(backup)) {
        memcpy(backup, packet + enc_off, enc_len);
        has_backup = 1;
    }

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int total_overhead = tunnel_hdr_size + (is_gcm ? AES128_GCM_TAG_SIZE : 0);

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        uint8_t *work_ptr = packet + enc_off;
        if (k > 0 && has_backup) memcpy(work_ptr, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0) continue;
        } 
        
        else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0) continue;
            if (!verify_decrypted_payload(work_ptr, enc_len, orig_proto)) continue;
        }

        memmove(packet + tunnel_off, work_ptr, enc_len);

        if (proto_flag == PROTO_FLAG_IPV4) {
            packet[IPV4_PROTO_OFF] = orig_proto;
            uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
            uint16_t new_totlen = old_totlen - (uint16_t)total_overhead;
            packet[IPV4_TOTLEN_OFF] = (uint8_t)(new_totlen >> 8);
            packet[IPV4_TOTLEN_OFF + 1] = (uint8_t)(new_totlen & 0xFF);
            packet[IPV4_CKSUM_OFF] = 0; packet[IPV4_CKSUM_OFF + 1] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(packet + ETH_HEADER_SIZE, IPV4_HDR_SIZE);
            packet[IPV4_CKSUM_OFF] = (uint8_t)(cksum >> 8);
            packet[IPV4_CKSUM_OFF + 1] = (uint8_t)(cksum & 0xFF);

            size_t dec_pkt_len = pkt_len - (size_t)total_overhead;
            int ip_hdr_len = (packet[ETH_HEADER_SIZE] & 0x0F) * 4;
            size_t transport_off = (size_t)ETH_HEADER_SIZE + (size_t)ip_hdr_len;

            if (dec_pkt_len > transport_off) {
                if (orig_proto == 6) {
                    size_t tcp_seg_len = dec_pkt_len - transport_off;
                    if (tcp_seg_len >= 20) {
                        uint8_t *tcp_seg = packet + transport_off;
                        tcp_seg[TCP_CKSUM_OFF] = 0;
                        tcp_seg[TCP_CKSUM_OFF + 1] = 0;
                        uint16_t tcp_cksum = crypto_calc_tcp_checksum(packet + ETH_HEADER_SIZE,
                                                                      ip_hdr_len,
                                                                      tcp_seg,
                                                                      (int)tcp_seg_len);
                        tcp_seg[TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
                        tcp_seg[TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
                    }
                } else if (orig_proto == 17) {
                    size_t udp_seg_len = dec_pkt_len - transport_off;
                    if (udp_seg_len >= 8) {
                        uint8_t *udp_seg = packet + transport_off;
                        udp_seg[UDP_CKSUM_OFF] = 0;
                        udp_seg[UDP_CKSUM_OFF + 1] = 0;
                        uint16_t udp_cksum = crypto_calc_udp_checksum(packet + ETH_HEADER_SIZE,
                                                                      ip_hdr_len,
                                                                      udp_seg,
                                                                      (int)udp_seg_len);
                        udp_seg[UDP_CKSUM_OFF] = (uint8_t)(udp_cksum >> 8);
                        udp_seg[UDP_CKSUM_OFF + 1] = (uint8_t)(udp_cksum & 0xFF);
                    }
                }
            }
        } 
        
        else {
            packet[IPV6_NEXTHDR_OFF] = orig_proto;
            uint16_t old_paylen = ((uint16_t)packet[IPV6_PAYLEN_OFF] << 8) | packet[IPV6_PAYLEN_OFF + 1];
            uint16_t new_paylen = old_paylen - (uint16_t)total_overhead;
            packet[IPV6_PAYLEN_OFF] = (uint8_t)(new_paylen >> 8);
            packet[IPV6_PAYLEN_OFF + 1] = (uint8_t)(new_paylen & 0xFF);
        }
        return (int)(pkt_len - total_overhead);
    }
    return -1;
}
