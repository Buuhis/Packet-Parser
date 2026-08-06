#include "app_context.h"
#include "utils/logger.h"

#include <string.h>

void app_context_dump(const app_context_t *ctx)
{
    log_info("Node ID: %d", ctx->cfg.node_id);
    log_info("Local IF: %s", ctx->cfg.local_if);
    log_info("SD-WAN_TUNNEL count: %zu", ctx->cfg.sdwan_tun_count);
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        log_info("SD-WAN_TUNNEL[%zu]: ifname=%s, gateway=%s, port=%d",
                 i, ctx->cfg.sdwan_tuns[i].ifname,
                 ctx->cfg.sdwan_tuns[i].gateway,
                 ctx->cfg.sdwan_tuns[i].port);
    }
    log_info("Encryption: %s (type: %s, key_len: %zu bytes)",
             ctx->cfg.encrypt.enabled ? "ON" : "OFF",
             ctx->cfg.encrypt.type == 0 ? "AES-GCM-128" : "AES-GCM-256",
             ctx->cfg.encrypt.key_len);
}
