#include "kernel_sync.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

/*
 * Push configuration to the kernel module (mwan_kmod)
 */
int kernel_sync_push_config(const app_context_t *ctx) {
    if (!ctx) return -1;
    
    log_info("");
    log_info("==========================================");
    log_info("Pushing routing state to mwan_kmod...");
    log_info("Overlay CIDR: %s", ctx->cfg.remote_cidr);
    log_info("Loopback: %s", ctx->cfg.loopback_ip);
    
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        const ne_tunnel_cfg_t *tun = &ctx->cfg.ne_tunnels[i];
        
        // Core Logic: Resolve interface name to index
        // Module relies entirely on external setup of these interfaces
        unsigned int idx = if_nametoindex(tun->ifname);
        
        if (idx == 0) {
            log_error("  [!] Interface %s not found in OS. Waiting for external setup...", tun->ifname);
        } else {
            log_info("  [*] Target TX Tunnel: %s -> ifindex: %u (Weight: %d)", 
                     tun->ifname, idx, tun->weight);
        }
    }
    log_info("==========================================");
    
    // TODO: Implement libnl-3 Generic Netlink message construction here
    // once the MWAN_GENL_FAMILY is strictly defined in mwan_kmod headers.
    
    return 0;
}

void kernel_sync_cleanup(void) {
    log_info("Cleaning up kernel synchronization resources...");
}
