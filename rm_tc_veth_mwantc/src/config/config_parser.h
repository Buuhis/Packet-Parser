#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "app_context.h"

int config_load_env(const char *path,
                    const char *node_id,
                    app_config_t *cfg);

#endif /* CONFIG_PARSER_H */

