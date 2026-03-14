#include "app_context.h"
#include "utils/logger.h"

#include <string.h>

void app_context_dump(const app_context_t *ctx)
{
    log_info("Node: %s", ctx->cfg.node_id);
    log_info("Local IF: %s", ctx->cfg.local_if);
    log_info("Remote CIDR: %s", ctx->cfg.remote_cidr);
    log_info("NE_TUNNEL count: %zu", ctx->cfg.ne_tunnel_count);
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        log_info("NE_TUNNEL[%zu]: ifname=%s, gateway=%s, port=%d",
                 i, ctx->cfg.ne_tunnels[i].ifname,
                 ctx->cfg.ne_tunnels[i].gateway,
                 ctx->cfg.ne_tunnels[i].port);
    }
}
