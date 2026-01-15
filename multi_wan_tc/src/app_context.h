#ifndef APP_CONTEXT_H
#define APP_CONTEXT_H

#include "config/config_parser.h"

typedef struct {
    app_cfg_t cfg;
} app_context_t;

int app_context_init(app_context_t *ctx, const char *config_path);
void app_context_dump(const app_context_t *ctx);

#endif /* APP_CONTEXT_H */ 
