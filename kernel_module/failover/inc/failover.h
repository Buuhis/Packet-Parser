#ifndef SDWAN_FAILOVER_H
#define SDWAN_FAILOVER_H

#include "bfd.h"
#include "app_context.h"

/* Copy/reconcile the current data-tunnel configuration. The first call owns
 * starting the background service and registers process-exit cleanup; later
 * calls are no-ops unless the tunnel snapshot changed. */
int failover_service_reconcile(const app_context_t *ctx);

#endif /* SDWAN_FAILOVER_H */
