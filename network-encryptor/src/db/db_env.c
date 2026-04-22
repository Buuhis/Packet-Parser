#include "../../inc/db_env.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void load_env_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[ENV] Could not open env file: %s\n", path);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = p;
        char *val = eq + 1;

        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        while (*val == ' ' || *val == '\t') val++;

        size_t len = strlen(val);
        while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r')) {
            val[--len] = '\0';
        }

        if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
            val[len - 1] = '\0';
            val++;
        }

        if (*key && *val) {
            setenv(key, val, 0);
        }
    }

    fclose(f);
}

const char *resolve_db_password(void) {
    const char *p = getenv("DB_PASS");
    if (p && *p) return p;
    p = getenv("PGPASSWORD");
    if (p && *p) return p;
    return NULL;
}

int parse_config_id_arg(const char *s, int *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
    }
    long v = strtol(s, NULL, 10);
    if (v < 0 || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}
