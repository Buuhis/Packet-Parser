#include "config_parser.h"
#include "utils/logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int parse_mac(const char *mac_str, unsigned char mac_bytes[6])
{
    int result = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
    return (result == 6) ? 0 : -1;
}

static char *trim_whitespace(char *str)
{
    if (str == NULL) return NULL;

    // Remove the leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;

    // Remove the tail whitespace
    char *end_ptr = str + strlen(str) - 1;
    while (end_ptr > str && isspace((unsigned char)*end_ptr)) {
        *end_ptr = '\0';
        end_ptr--;
    }

    return str;
}

int config_load_env(const char *path,
                    const char *node_id,
                    app_config_t *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }

    char prefix[32];
    snprintf(prefix, sizeof(prefix), "%s_", node_id);
    for (char *p = prefix; *p; p++) *p = toupper(*p);

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim_whitespace(line);
        if (*s == '#' || *s == '\0')
            continue;

        char *eq = strchr(s, '=');
        if (!eq)
            continue;

        *eq = 0;
        char *key = trim_whitespace(s);
        char *val = trim_whitespace(eq + 1);

        if (strncmp(key, prefix, strlen(prefix)) != 0)
            continue;

        key += strlen(prefix);

        /* ---- simple fields ---- */
        if (!strcmp(key, "LOCAL_IF")) {
            strncpy(cfg->local_if, val, sizeof(cfg->local_if)-1);
        } else if (!strcmp(key, "REMOTE_CIDR")) {
            strncpy(cfg->remote_cidr, val, sizeof(cfg->remote_cidr)-1);

        /* ---- LAN ---- */
        } else if (!strcmp(key, "LAN_IP")) {
            strncpy(cfg->lan.ip, val, sizeof(cfg->lan.ip)-1);
        } else if (!strcmp(key, "LAN_GW")) {
            strncpy(cfg->lan.gw, val, sizeof(cfg->lan.gw)-1);
        } else if (!strcmp(key, "LAN_DST_MAC")) {
            parse_mac(val, cfg->lan.dst_mac);

        /* ---- DATAPLANE ---- */
        } else if (!strcmp(key, "DATAPLANE_VETH_IN")) {
            strncpy(cfg->dataplane.veth_in, val,
                    sizeof(cfg->dataplane.veth_in)-1);
        } else if (!strcmp(key, "DATAPLANE_VETH_OUT")) {
            strncpy(cfg->dataplane.veth_out, val,
                    sizeof(cfg->dataplane.veth_out)-1);
        } else if (!strcmp(key, "DATAPLANE_MTU")) {
            cfg->dataplane.mtu = atoi(val);

        /* ---- WAN COUNT ---- */
        } else if (!strcmp(key, "WANS_COUNT")) {
            cfg->wan_count = atoi(val);

        /* ---- WAN ARRAY ---- */
        } else if (!strncmp(key, "WANS_", 5)) {
            int idx;
            char field[32];
            if (sscanf(key, "WANS_%d_%31s", &idx, field) == 2 &&
                idx < MAX_WANS) {

                wan_cfg_t *w = &cfg->wans[idx];

                if (!strcmp(field, "NAME"))
                    strncpy(w->name, val, sizeof(w->name)-1);
                else if (!strcmp(field, "IFNAME"))
                    strncpy(w->ifname, val, sizeof(w->ifname)-1);
                else if (!strcmp(field, "GATEWAY"))
                    strncpy(w->gateway, val, sizeof(w->gateway)-1);
                else if (!strcmp(field, "WEIGHT"))
                    w->weight = atoi(val);
                else if (!strcmp(field, "DST_MAC")) {
                    if (parse_mac(val, w->dst_mac) != 0) {
                        log_error("Failed to parse DST_MAC for WAN[%d]: '%s'", idx, val);
                        // Có thể set default hoặc return error
                    } else {
                        log_debug("WAN[%d] DST_MAC = %02x:%02x:%02x:%02x:%02x:%02x",
                                  idx, w->dst_mac[0], w->dst_mac[1], w->dst_mac[2],
                                  w->dst_mac[3], w->dst_mac[4], w->dst_mac[5]);
                    }
                }
            }
        }
    }

    fclose(f);
    return 0;
}
