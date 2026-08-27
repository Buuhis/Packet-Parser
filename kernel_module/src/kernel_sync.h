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

/* APPLIED means the kernel acknowledged the config. DEFERRED is used only
 * while a PQC config waits for its authenticated userspace session key. */
enum kernel_sync_result kernel_sync_push_config(const app_context_t *ctx);

/* Query the peer tunnel IPv4 address learned at runtime by the kernel's
 * point-to-point discovery protocol. */
int kernel_sync_get_tunnel_peer(const char *ifname, char *peer_ip,
                                size_t peer_ip_len);
int kernel_sync_set_tunnel_state(const char *ifname, uint32_t generation,
                                 uint32_t sequence, bool up);
int kernel_sync_get_tunnel_status(const char *ifname, bool *up);

/* Cleans up any resources */
void kernel_sync_cleanup(void);

#endif /* KERNEL_SYNC_H */
