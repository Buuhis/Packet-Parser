#ifndef CPU_TUNE_H
#define CPU_TUNE_H

#include "../app_context.h"

/* Apply all CPU tuning for optimal multi-core performance.
 * Includes: multi-queue, RSS sdfn, IRQ affinity, XPS, RPS, mq qdisc.
 * Saves original values for later restoration. */
int cpu_tune_apply(const app_context_t *ctx);

/* Restore all tuned values back to their original state */
void cpu_tune_restore(void);

#endif /* CPU_TUNE_H */
