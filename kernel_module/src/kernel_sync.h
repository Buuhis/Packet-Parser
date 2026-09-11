#ifndef KERNEL_SYNC_H
#define KERNEL_SYNC_H

#include "app_context.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum kernel_sync_result {
    KERNEL_SYNC_ERROR = -1,
    KERNEL_SYNC_APPLIED = 0,
    KERNEL_SYNC_DEFERRED = 1,
};

/* APPLIED means the kernel acknowledged the active datapath config. DEFERRED
 * means PQC is waiting for its authenticated session key; tunnel discovery
 * has nevertheless been registered independently with the kernel. */
enum kernel_sync_result kernel_sync_push_config(const app_context_t *ctx);
uint32_t kernel_sync_current_config_generation(void);
int kernel_sync_update_tunnel_weights(const app_context_t *ctx);
int kernel_sync_stage_pqc_key(int profile_id, uint64_t epoch, uint8_t key_id,
                              const uint8_t key[32]);
int kernel_sync_activate_pqc_key(int profile_id, uint64_t epoch,
                                 uint8_t key_id);
int kernel_sync_retire_pqc_key(int profile_id, uint64_t epoch,
                               uint8_t key_id);
int kernel_sync_abort_pqc_key(int profile_id, uint64_t epoch,
                              uint8_t key_id);

struct kernel_pqc_key_state {
    uint32_t generation;
    uint64_t epoch;
    uint8_t state;
    uint8_t current_id;
    uint8_t prev_id;
    uint8_t next_id;
};

struct kernel_tunnel_state {
    uint32_t generation;
    uint32_t sequence;
    bool up;
};
int kernel_sync_get_pqc_key_state(int profile_id,
                                  struct kernel_pqc_key_state *state);

/* Query the peer tunnel IPv4 address learned at runtime by the kernel's
 * point-to-point discovery protocol. */
int kernel_sync_get_tunnel_peer(const char *ifname, char *peer_ip,
                                size_t peer_ip_len);
int kernel_sync_set_tunnel_state(const char *ifname, uint32_t generation,
                                 uint32_t sequence, bool up);
int kernel_sync_set_tunnel_state_by_ifindex(unsigned int ifindex,
                                            uint32_t generation,
                                            uint32_t sequence, bool up);
int kernel_sync_get_tunnel_status(const char *ifname, bool *up);
int kernel_sync_get_tunnel_state_by_ifindex(
    unsigned int ifindex, struct kernel_tunnel_state *state);
int kernel_sync_rebind_tunnel(int node_id, uint32_t generation,
                              unsigned int old_ifindex,
                              unsigned int new_ifindex);

/* Cleans up any resources */
void kernel_sync_cleanup(void);

#endif /* KERNEL_SYNC_H */
