#ifndef CRYPTO_LAYER3_H
#define CRYPTO_LAYER3_H

#include "packet_crypto.h"

int crypto_layer3_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer3_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

#endif
