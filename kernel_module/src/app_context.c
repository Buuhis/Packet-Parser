#include "app_context.h"
#include "utils/logger.h"

#include <string.h>

void app_context_dump(const app_context_t *ctx)
{
    log_info("Profile ID: %d", ctx->cfg.node_id);
    log_info("SD-WAN_TUNNEL count: %zu", ctx->cfg.sdwan_tun_count);
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &ctx->cfg.sdwan_tuns[i];

        log_info("SD-WAN_TUNNEL[%zu]: tunnel=%s, physical=%s, ip=%s, segment=%d, weight=%d",
                 i, tun->tunnel_ifname, tun->physical_ifname,
                 tun->tunnel_ip, tun->segment_id, tun->weight);
    }
    log_info("Profile policy: weight=%s, latency=%s/%ds, loss=%s/%ds",
             ctx->cfg.weight_enabled ? "ON" : "OFF",
             ctx->cfg.latency_enabled ? "ON" : "OFF",
             ctx->cfg.latency_duration,
             ctx->cfg.loss_enabled ? "ON" : "OFF",
             ctx->cfg.loss_duration);
    if (!ctx->cfg.encrypt.enabled) {
        log_info("Encryption action: BYPASS (encryption OFF)");
    } else {
        const char *key_state =
            ctx->cfg.encrypt.type == 2 && ctx->cfg.encrypt.key_len == 0 ?
            ", key=PENDING_HANDSHAKE" : "";

        log_info("Encryption action: L%u, method=%s, key_len=%zu bytes%s",
                 ctx->cfg.encrypt.layer,
                 ctx->cfg.encrypt.type == 0 ? "AES-GCM-128" :
                 (ctx->cfg.encrypt.type == 1 ? "AES-GCM-256" : "PQC-GCM"),
                 ctx->cfg.encrypt.key_len, key_state);
    }
}
