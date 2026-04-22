#include "../../inc/crypto_policy_utils.h"

#include "../../inc/packet_crypto.h"

#include <stddef.h>

void crypto_apply_default_from_cfg(const struct app_config *cfg) {
    if (!cfg)
        return;
    packet_crypto_set_mode(cfg->crypto_mode);
    packet_crypto_set_aes_bits(cfg->aes_bits);
    packet_crypto_set_nonce_size(cfg->nonce_size);
    if (cfg->encrypt_layer == 3)
        packet_crypto_set_fake_protocol((uint8_t)(cfg->fake_protocol & 0xFF));
    packet_crypto_set_policy_id(0);

    packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
}

void crypto_apply_from_policy(const struct crypto_policy *cp) {
    if (!cp)
        return;

    packet_crypto_set_mode(cp->crypto_mode);
    packet_crypto_set_aes_bits(cp->aes_bits);
    packet_crypto_set_nonce_size(cp->nonce_size);


    if (cp->action == POLICY_ACTION_ENCRYPT_L2)
        packet_crypto_set_encrypt_layer(2);
    else if (cp->action == POLICY_ACTION_ENCRYPT_L3)
        packet_crypto_set_encrypt_layer(3);
    else if (cp->action == POLICY_ACTION_ENCRYPT_L4)
        packet_crypto_set_encrypt_layer(4);

    if (cp->action == POLICY_ACTION_ENCRYPT_L3)
        packet_crypto_set_fake_protocol(99);
    packet_crypto_set_policy_id((uint8_t)cp->id);
}

const struct crypto_policy *crypto_select_policy_for_flow(const struct app_config *cfg,
                                                             uint32_t src_ip,
                                                             uint32_t dst_ip,
                                                             uint16_t src_port,
                                                             uint16_t dst_port,
                                                             uint8_t protocol) {
    if (!cfg)
        return NULL;
    if (cfg->profile_count <= 0)
        return NULL;

    int profile_idx = config_select_profile_for_flow((struct app_config *)cfg, src_ip, dst_ip);
    if (profile_idx < 0)
        return NULL;

    return config_select_crypto_policy((struct app_config *)cfg,
                                        profile_idx,
                                        src_ip, dst_ip,
                                        src_port, dst_port,
                                        protocol);
}

