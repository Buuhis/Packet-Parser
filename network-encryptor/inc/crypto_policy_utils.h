#ifndef CRYPTO_POLICY_UTILS_H
#define CRYPTO_POLICY_UTILS_H

#include <stdint.h>
#include "config.h"


void crypto_apply_default_from_cfg(const struct app_config *cfg);


void crypto_apply_from_policy(const struct crypto_policy *cp);


const struct crypto_policy *crypto_select_policy_for_flow(const struct app_config *cfg,
                                                            uint32_t src_ip,
                                                            uint32_t dst_ip,
                                                            uint16_t src_port,
                                                            uint16_t dst_port,
                                                            uint8_t protocol);

#endif 

