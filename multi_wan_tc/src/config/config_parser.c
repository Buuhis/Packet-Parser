#define _POSIX_C_SOURCE 202405L

#include "config_parser.h"
#include "../utils/logger.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char *trim_left(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static void trim_right_inplace(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[n - 1] = '\0';
        n--;
    }
}

/* Returns 1 if line is empty or comment, else 0 */
static int is_ignorable_line(const char *s) {
    if (!s) return 1;
    while (*s && isspace((unsigned char)*s)) s++;
    return (*s == '\0' || *s == '#');
}

static int safe_copy(char *dst, size_t dst_sz, const char *src) {
    if (!dst || !src || dst_sz == 0) return -1;
    size_t len = strlen(src);
    if (len >= dst_sz) return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

int config_validate(const app_cfg_t *cfg) {
    if (!cfg) {
        log_error("config_validate: cfg is NULL");
        return -1;
    }
    if (cfg->local_if[0] == '\0') {
        log_error("Config missing: local <ifname>");
        return -1;
    }
    if (cfg->remote_cidr[0] == '\0') {
        log_error("Config missing: remote <CIDR>");
        return -1;
    }
    if (cfg->wan_count == 0) {
        log_error("Config missing: at least one 'wan <ifname> <gateway>'");
        return -1;
    }
    for (size_t i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].ifname[0] == '\0' || cfg->wans[i].gw[0] == '\0') {
            log_error("Invalid wan entry at index %zu", i);
            return -1;
        }
    }
    return 0;
}

void config_dump(const app_cfg_t *cfg) {
    if (!cfg) return;
    log_info("==== Loaded config ====");
    log_info("local  : %s", cfg->local_if);
    log_info("remote : %s", cfg->remote_cidr);
    log_info("wans   : %zu", cfg->wan_count);
    for (size_t i = 0; i < cfg->wan_count; i++) {
        log_info("  wan[%zu] if=%s gw=%s", i, cfg->wans[i].ifname, cfg->wans[i].gw);
    }
    log_info("=======================");
}

int config_load_file(const char *path, app_cfg_t *out) {
    if (!path || !out) {
        log_error("config_load_file: invalid args");
        return -1;
    }

    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_error("Failed to open config '%s': %s", path, strerror(errno));
        return -1;
    }

    char line[512];
    int lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;

        trim_right_inplace(line);
        char *p = trim_left(line);

        if (is_ignorable_line(p)) continue;

        /* Tokenize: keyword + args */
        char *save = NULL;
        char *kw = strtok_r(p, " \t", &save);
        if (!kw) continue;

        if (strcmp(kw, "local") == 0) {
            char *ifname = strtok_r(NULL, " \t", &save);
            if (!ifname) {
                log_error("Config parse error line %d: 'local' requires <ifname>", lineno);
                fclose(fp);
                return -1;
            }
            if (safe_copy(out->local_if, sizeof(out->local_if), ifname) != 0) {
                log_error("Config parse error line %d: local ifname too long", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(kw, "remote") == 0) {
            char *cidr = strtok_r(NULL, " \t", &save);
            if (!cidr) {
                log_error("Config parse error line %d: 'remote' requires <CIDR>", lineno);
                fclose(fp);
                return -1;
            }
            if (safe_copy(out->remote_cidr, sizeof(out->remote_cidr), cidr) != 0) {
                log_error("Config parse error line %d: remote CIDR too long", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(kw, "wan") == 0) {
            char *ifname = strtok_r(NULL, " \t", &save);
            char *gw     = strtok_r(NULL, " \t", &save);
            if (!ifname || !gw) {
                log_error("Config parse error line %d: 'wan' requires <ifname> <gateway>", lineno);
                fclose(fp);
                return -1;
            }
            if (out->wan_count >= MAX_WANS) {
                log_error("Config parse error line %d: too many WANs (max %d)", lineno, MAX_WANS);
                fclose(fp);
                return -1;
            }
            wan_cfg_t *w = &out->wans[out->wan_count];

            if (safe_copy(w->ifname, sizeof(w->ifname), ifname) != 0) {
                log_error("Config parse error line %d: wan ifname too long", lineno);
                fclose(fp);
                return -1;
            }
            if (safe_copy(w->gw, sizeof(w->gw), gw) != 0) {
                log_error("Config parse error line %d: wan gateway too long", lineno);
                fclose(fp);
                return -1;
            }
            out->wan_count++;
        } else {
            log_warn("Config parse warning line %d: unknown keyword '%s' (ignored)", lineno, kw);
        }
    }

    fclose(fp);

    if (config_validate(out) != 0) {
        log_error("Config validation failed");
        return -1;
    }

    return 0;
}

