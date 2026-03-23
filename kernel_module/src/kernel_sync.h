#ifndef KERNEL_SYNC_H
#define KERNEL_SYNC_H

#include "app_context.h"

/* Returns 0 on success, < 0 on error */
int kernel_sync_push_config(const app_context_t *ctx);

/* Cleans up any resources */
void kernel_sync_cleanup(void);

#endif /* KERNEL_SYNC_H */
