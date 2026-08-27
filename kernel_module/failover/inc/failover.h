#ifndef SDWAN_FAILOVER_H
#define SDWAN_FAILOVER_H

#include "bfd.h"
#include "app_context.h"

/* Replace the desired data-tunnel snapshot after a config reached the kernel.
 * The worker reconciles sessions incrementally; this call never waits for BFD
 * discovery or changes kernel path selection. */
int failover_service_reconcile(const app_context_t *ctx);

/* Stop the worker and release every BFD session. */
void failover_service_stop(void);

#endif /* SDWAN_FAILOVER_H */
