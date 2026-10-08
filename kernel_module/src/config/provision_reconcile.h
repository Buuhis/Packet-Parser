#ifndef PROVISION_RECONCILE_H
#define PROVISION_RECONCILE_H

#include "app_context.h"

#include <stdbool.h>
#include <stddef.h>

/* Event-driven provisioning state.  Interface appearance is acknowledged
 * only when the control plane sends -a; there is deliberately no polling
 * worker behind this API. */
enum provision_state {
    PROVISION_UNPROVISIONED = 0,
    PROVISION_WAIT_TUNNEL,
    PROVISION_WAIT_KEY,
    PROVISION_READY,
};

enum provision_transaction_kind {
    PROVISION_TX_NONE = 0,
    PROVISION_TX_FULL_APPLY,
    PROVISION_TX_SECURITY_EDIT,
};

/* ACTIVE remains in running_ctx.  This transaction owns the candidate until
 * handshake + kernel ACK make it safe to commit. */
void provision_transaction_stage(enum provision_transaction_kind kind,
                                 const app_context_t *candidate,
                                 uint64_t generation,
                                 uint64_t previous_generation);
bool provision_transaction_snapshot(int profile_id,
                                    app_context_t *candidate,
                                    enum provision_transaction_kind *kind,
                                    uint64_t *generation,
                                    uint64_t *previous_generation);
bool provision_transaction_any(void);
int provision_transaction_update(const app_context_t *candidate,
                                 uint64_t generation);
int provision_transaction_replace_full_apply(const app_context_t *candidate,
                                             uint64_t expected_generation,
                                             uint64_t new_generation);
void provision_transaction_finish(uint64_t generation);
void provision_transaction_cancel(uint64_t generation);

void provision_reconcile_accept(const app_context_t *desired);
void provision_reconcile_clear(void);
void provision_reconcile_note_key(int profile_id, bool ready);
int provision_reconcile_validate_profile(int profile_id);
bool provision_reconcile_tunnel_desired(int profile_id, const char *ifname);
bool provision_reconcile_tunnel_acknowledged(int profile_id,
                                             const char *ifname);
int provision_reconcile_ack_tunnel(int profile_id, const char *ifname);
void provision_reconcile_rollback_tunnel(int profile_id, const char *ifname,
                                         bool remove_entry);

/* Build the runtime snapshot from interfaces acknowledged by -id/-a.  The
 * desired snapshot is never modified, so a later -a can retry exactly one
 * waiting tunnel without enabling other interfaces merely because they have
 * appeared in the meantime. */
int provision_reconcile_build_present(const app_context_t *desired,
                                      app_context_t *present,
                                      size_t *missing_count);
enum provision_state provision_reconcile_state(void);

#endif
