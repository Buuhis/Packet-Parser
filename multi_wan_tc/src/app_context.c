#include "app_context.h"
#include "utils/logger.h"
#include "config/config_parser.h"

#include <string.h>

// int app_context_init(app_context_t *ctx, const char *config_path) {
//     if (!ctx || !config_path) {
//         log_error("app_context_init: invalid args");
//         return -1;
//     }
//     memset(ctx, 0, sizeof(*ctx));

//     if (config_load_file(config_path, &ctx->cfg) != 0) {
//         log_error("Failed to load config: %s", config_path);
//         return -1;
//     }
//     return 0;
// }

// void app_context_dump(const app_context_t *ctx) {
//     if (!ctx) return;
//     config_dump(&ctx->cfg);
// }

int app_context_init(app_context_t *ctx,
                     const char *config_path,
                     const char *node_id)
{
    memset(ctx, 0, sizeof(*ctx));

    if (config_load_env(config_path, node_id, &ctx->cfg) != 0) {
        log_error("Failed to load config for node %s", node_id);
        return -1;
    }

    strncpy(ctx->cfg.node_id, node_id, sizeof(ctx->cfg.node_id) - 1);

    /* basic validation */
    if (ctx->cfg.wan_count == 0) {
        log_error("No WAN defined for node %s", node_id);
        return -1;
    }

    if (ctx->cfg.dataplane.veth_in[0] == '\0' ||
        ctx->cfg.dataplane.veth_out[0] == '\0') {
        log_error("Dataplane veth not defined");
        return -1;
    }

    /* Log WAN configuration for debugging */
    for (size_t i = 0; i < ctx->cfg.wan_count; i++) {
        log_info("WAN[%zu]: ifname=%s, dst_mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 i, ctx->cfg.wans[i].ifname,
                 ctx->cfg.wans[i].dst_mac[0], ctx->cfg.wans[i].dst_mac[1],
                 ctx->cfg.wans[i].dst_mac[2], ctx->cfg.wans[i].dst_mac[3],
                 ctx->cfg.wans[i].dst_mac[4], ctx->cfg.wans[i].dst_mac[5]);
    }

    return 0;
}

void app_context_dump(const app_context_t *ctx)
{
    log_info("Node: %s", ctx->cfg.node_id);
    log_info("Local IF: %s", ctx->cfg.local_if);
    log_info("Remote CIDR: %s", ctx->cfg.remote_cidr);
    log_info("WAN count: %zu", ctx->cfg.wan_count);
}
