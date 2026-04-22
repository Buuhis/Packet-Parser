#include "../inc/config.h"
#include "../inc/db_env.h"
#include "../inc/db_runtime.h"
#include "../inc/main_diag.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -id <id1> [id2 ...]\n", prog);
}

int main(int argc, char **argv) {
    load_env_from_file("/opt/db_test.env");
    const char *db_pass = resolve_db_password();
    if (!db_pass || !*db_pass) {
        fprintf(stderr, "[FATAL] Missing DB_PASS/PGPASSWORD\n");
        return 1;
    }

    int ids[32];
    int n = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0) continue;
        if (n >= 32) break;
        if (parse_config_id_arg(argv[i], &ids[n]) != 0) {
            usage(argv[0]);
            return 1;
        }
        n++;
    }
    if (n <= 0) {
        usage(argv[0]);
        return 1;
    }

    struct app_config merged;
    if (build_merged_config(&merged, ids, n, db_pass) != 0) {
        fprintf(stderr, "[FAIL] build_merged_config failed\n");
        return 1;
    }

    main_diag_log_loaded_config(&merged, (n == 1) ? ids[0] : -1);
    fprintf(stdout, "[OK] DB loader test passed for %d config id(s)\n", n);
    return 0;
}
