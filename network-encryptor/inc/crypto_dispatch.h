#ifndef CRYPTO_DISPATCH_H
#define CRYPTO_DISPATCH_H

#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "packet_crypto.h"


struct crypto_dispatch_ctx {
    struct packet_crypto_ctx *base_ctx;                
    struct packet_crypto_ctx *per_policy_ctx;           
    int *per_policy_ready;                             
    struct crypto_policy *policies;
    int policy_count;
    int (*policy_index_by_action_id)[256];
    struct packet_crypto_ctx *prev_per_policy_ctx;
    int *prev_per_policy_ready;
    struct crypto_policy *prev_policies;
    int prev_policy_count;
    int (*prev_policy_index_by_action_id)[256];
    int prev_grace_active;
};


int crypto_l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out);


int crypto_l4_extract_policy_id_ipv4(uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out,
                                      int *nonce_size_out);


int crypto_decrypt_packet_auto_by_action(
    int crypto_enabled,
    struct app_config *cfg,
    struct crypto_dispatch_ctx *dctx,
    int action_layer,
    uint8_t *pkt, uint32_t *pkt_len,
    uint8_t *scratch, size_t scratch_sz);

#endif 

