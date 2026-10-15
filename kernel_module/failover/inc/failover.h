#ifndef SDWAN_FAILOVER_H
#define SDWAN_FAILOVER_H

#include "bfd.h"
#include "app_context.h"

/* Replace the desired data-tunnel snapshot after a config reached the kernel.
 * The worker reconciles sessions incrementally and publishes only stabilized
 * BFD state changes back to the matching kernel config generation. */
int failover_service_reconcile(const app_context_t *ctx,
                               uint32_t config_generation);

/* Serialize an active kernel config commit with the failover worker.  The
 * caller must end every update it begins, including failed Netlink pushes. */
void failover_config_update_begin(void);
void failover_config_update_end(void);

/* Stop the worker and release every BFD session. */
void failover_service_stop(void);

#endif /* SDWAN_FAILOVER_H */
