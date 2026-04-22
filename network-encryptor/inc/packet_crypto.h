#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AES128_KEY_SIZE       16
#define AES256_KEY_SIZE       32
#define AES_MAX_KEY_SIZE      32
#define AES128_BLOCK_SIZE     16
#define AES128_IV_SIZE        16
#define AES128_ROUND_KEY_SIZE 256

#define ETH_HEADER_SIZE       14

#define PROTO_FLAG_IPV4  0
#define PROTO_FLAG_IPV6  1

#define KEY_SLOT_PREV    0
#define KEY_SLOT_CURRENT 1
#define KEY_SLOT_NEXT    2
#define KEY_SLOT_COUNT   3

struct packet_crypto_ctx {
    uint8_t master_key[AES_MAX_KEY_SIZE];
    uint8_t keys[KEY_SLOT_COUNT][AES_MAX_KEY_SIZE];
    bool initialized;
};

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE]);

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx);

uint32_t packet_crypto_next_counter(void);
void packet_crypto_reset_counter(void);

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot);

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx);

void packet_crypto_set_ethertype(uint16_t fake_ipv4, uint16_t fake_ipv6);
uint16_t packet_crypto_get_fake_ethertype_ipv4(void);
uint16_t packet_crypto_get_fake_ethertype_ipv6(void);

void packet_crypto_set_fake_protocol(uint8_t proto);
uint8_t packet_crypto_get_fake_protocol(void);


void packet_crypto_set_policy_id(uint8_t policy_id);
uint8_t packet_crypto_get_policy_id(void);

#define AES128_GCM_TAG_SIZE  16

int packet_crypto_get_tunnel_hdr_size(void);

void crypto_write_l3_tunnel_header(uint8_t *buf, const uint8_t *nonce,
                                    int nonce_size, uint8_t policy_id,
                                    uint8_t orig_proto);
void crypto_read_l3_tunnel_header(const uint8_t *buf, int nonce_size,
                                   uint8_t *nonce_out, uint8_t *proto_flag,
                                   uint8_t *policy_id, uint8_t *orig_proto);

void packet_crypto_set_encrypt_layer(int layer);

void packet_crypto_set_mode(int mode);
int  packet_crypto_get_mode(void);

void packet_crypto_set_nonce_size(int size);
int  packet_crypto_get_nonce_size(void);

void packet_crypto_set_aes_bits(int bits);
int  packet_crypto_get_aes_bits(void);

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           uint8_t tag_out[AES128_GCM_TAG_SIZE]);

int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           const uint8_t tag[AES128_GCM_TAG_SIZE]);

void crypto_generate_nonce(uint32_t counter, uint8_t proto_flag,
                           uint8_t *out_nonce, int *out_nonce_len);

void crypto_nonce_to_iv(const uint8_t *nonce, int nonce_size,
                        uint8_t iv[AES128_IV_SIZE]);

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE],
                            const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len);

void crypto_write_counter(uint8_t *packet, const uint8_t *nonce,
                          int nonce_size, uint8_t marker_byte, uint8_t policy_id);
void crypto_read_counter(const uint8_t *packet, int nonce_size,
                         uint8_t *nonce_out, uint8_t *policy_id, uint8_t *proto_flag);

void crypto_restore_ipv4_header(uint8_t *packet, size_t pkt_len);
void crypto_restore_ipv6_header(uint8_t *packet, size_t pkt_len);

uint16_t crypto_calc_ip_checksum(const uint8_t *ip_hdr, int hdr_len);

uint16_t crypto_calc_tcp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *tcp_seg, int tcp_seg_len);

uint16_t crypto_calc_udp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *udp_seg, int udp_seg_len);

#endif