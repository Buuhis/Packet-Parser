#ifndef KERNEL_SYNC_H
#define KERNEL_SYNC_H

#include "app_context.h"

enum kernel_sync_result {
    KERNEL_SYNC_ERROR = -1,
    KERNEL_SYNC_APPLIED = 0,
    KERNEL_SYNC_DEFERRED = 1,
};

/* APPLIED means the kernel acknowledged the config. DEFERRED is used only
 * while a PQC config waits for its authenticated userspace session key. */
enum kernel_sync_result kernel_sync_push_config(const app_context_t *ctx);

/* Cleans up any resources */
void kernel_sync_cleanup(void);

#endif /* KERNEL_SYNC_H */
