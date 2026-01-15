#include "app_context.h"
#include "utils/logger.h"
#include "config/config_parser.h"

#include <string.h>

int app_context_init(app_context_t *ctx, const char *config_path) {
    if (!ctx || !config_path) {
        log_error("app_context_init: invalid args");
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));

    if (config_load_file(config_path, &ctx->cfg) != 0) {
        log_error("Failed to load config: %s", config_path);
        return -1;
    }
    return 0;
}

void app_context_dump(const app_context_t *ctx) {
    if (!ctx) return;
    config_dump(&ctx->cfg);
}
