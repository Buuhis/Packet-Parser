#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "packet_crypto.h"

#define FRAG_HDR_SIZE       3
#define FRAG_L4_HDR_SIZE    4
#define FRAG_FLAG_BIT       0x80
#define FRAG_MTU            1500


#define FRAG_TABLE_SIZE     4096
#define FRAG_TIMEOUT_NS     (200ULL * 1000000ULL)

struct frag_entry {
    uint16_t pkt_id;
    uint8_t  data[1600];
    uint32_t data_len;
    uint8_t  eth_hdr[14];
    uint8_t  ip_hdr[60];
    int      ip_hdr_len;
    uint8_t  orig_proto;
    uint64_t timestamp_ns;
    int      valid;
    uint16_t transport_hdr_len;
};

struct frag_table {
    struct frag_entry entries[FRAG_TABLE_SIZE];
};

uint16_t frag_next_pkt_id(void);

void frag_table_init(struct frag_table *ft);

void frag_table_gc(struct frag_table *ft);


static inline int frag_need_split(uint32_t pkt_len) {
    int overhead = packet_crypto_get_tunnel_hdr_size() + FRAG_HDR_SIZE;
    if (packet_crypto_get_mode() == 1)
        overhead += 16;
    return (pkt_len + overhead) > FRAG_MTU;
}


static inline int frag_need_split_l4(uint32_t pkt_len) {
    int overhead = packet_crypto_get_tunnel_hdr_size() + FRAG_L4_HDR_SIZE;
    if (packet_crypto_get_mode() == 1)
        overhead += 16;
    return (pkt_len + overhead) > FRAG_MTU;
}


static inline int frag_need_split_l2(uint32_t pkt_len) {
    int nonce_size = packet_crypto_get_nonce_size();
    int overhead = nonce_size;
    if (packet_crypto_get_mode() == 1)
        overhead += 16;
    return (pkt_len + overhead) > FRAG_MTU;
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint8_t *frag1, uint32_t *frag1_len,
                           uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index);

int frag_decrypt_fragment(struct packet_crypto_ctx *ctx,
                          uint8_t *packet, size_t pkt_len,
                          uint16_t *out_pkt_id, uint8_t *out_frag_index);

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l4(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment_l4(const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_decrypt_fragment_l4(struct packet_crypto_ctx *ctx,
                             uint8_t *packet, size_t pkt_len,
                             uint16_t *out_pkt_id, uint8_t *out_frag_index);

int frag_try_reassemble_l4(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l2(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment_l2(const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble_l2(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

#endif