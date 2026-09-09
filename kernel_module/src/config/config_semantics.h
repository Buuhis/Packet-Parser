#ifndef CONFIG_SEMANTICS_H
#define CONFIG_SEMANTICS_H

#include "app_context.h"

#include <stdbool.h>

/* Compare only values consumed by the running userspace/kernel datapath.
 * Database metadata and structure padding are deliberately excluded. */
bool config_runtime_equal(const app_config_t *left,
                          const app_config_t *right);

/* Compare only values serialized by kernel_sync_push_config(). */
bool config_kernel_equal(const app_config_t *left,
                         const app_config_t *right);

/* True when the only values visible to the kernel that changed are tunnel
 * weights. This permits an in-place update without replacing runtime state. */
bool config_kernel_weight_only_changed(const app_config_t *left,
                                       const app_config_t *right);

/* Compare the identity used to reconcile BFD sessions. */
bool config_failover_equal(const app_config_t *left,
                           const app_config_t *right);

/* A change involving PQC needs a handshake lifecycle restart only when the
 * encryption policy itself changes. Load-balancing/monitoring policy does
 * not affect the established PQC identity or session. */
bool config_pqc_policy_changed(const app_config_t *old_cfg,
                               const app_config_t *new_cfg);

/* True only for fields that the current daemon does not consume. Unknown
 * fields return false so future datapath fields keep the conservative reload
 * behaviour until they are explicitly classified. */
bool config_edit_field_is_metadata(const char *qualified_field);

#endif /* CONFIG_SEMANTICS_H */
