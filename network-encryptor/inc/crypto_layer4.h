#ifndef CRYPTO_LAYER4_H
#define CRYPTO_LAYER4_H

#include "packet_crypto.h"


int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len);

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

int crypto_layer4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto, size_t remaining);

int crypto_layer4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *transport_hdr, int transport_hdr_len,
    const uint8_t *app_payload, uint32_t app_payload_len,
    uint16_t pkt_id, uint8_t frag_index, uint32_t tcp_seq_delta,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);
int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);
#endif
