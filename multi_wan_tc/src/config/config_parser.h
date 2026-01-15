#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stddef.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define MAX_WANS 16

typedef struct {
    char ifname[IFNAMSIZ];  /* e.g., "wan0" */
    char gw[64];            /* e.g., "192.168.1.1" */
} wan_cfg_t;

typedef struct {
    char local_if[IFNAMSIZ];    /* e.g., "eth0" */
    char remote_cidr[64];       /* e.g., "192.168.100.0/24" */
    wan_cfg_t wans[MAX_WANS];
    size_t wan_count;
} app_cfg_t;

/* Parse config file into app_cfg_t.
 * Returns 0 on success, -1 on error (prints reason to logger).
 */
int config_load_file(const char *path, app_cfg_t *out);

/* Validate config fields (called inside config_load_file, exposed for tests). */
int config_validate(const app_cfg_t *cfg);

/* Debug dump of loaded config (no side effects). */
void config_dump(const app_cfg_t *cfg);

#endif /* CONFIG_PARSER_H */

