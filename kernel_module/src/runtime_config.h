#ifndef RUNTIME_CONFIG_H
#define RUNTIME_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/* Start a new full-config generation. Any asynchronous callback carrying an
 * older generation becomes stale as soon as this function returns. */
uint64_t runtime_config_begin_reload(uint64_t *previous_generation);

/* Restore the previous generation when a candidate fails before commit. */
void runtime_config_cancel_reload(uint64_t generation,
                                  uint64_t previous_generation);

/* Serialize the live userspace context and full-config Netlink publishes. */
void runtime_config_lock(void);
void runtime_config_unlock(void);

/* The caller must hold runtime_config_lock(). */
bool runtime_config_generation_is_current_locked(uint64_t generation);

#endif
