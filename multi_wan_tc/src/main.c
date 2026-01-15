#include "app_context.h"
#include "utils/logger.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --config <path> --dump-config\n"
        "\n"
        "Step 1 only: parse config and print it. No kernel networking changes.\n",
        prog
    );
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    int dump = 0;

    log_set_level(LOG_INFO);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--dump-config") == 0) {
            dump = 1;
        } else if (strcmp(argv[i], "--debug") == 0) {
            log_set_level(LOG_DEBUG);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            log_warn("Unknown arg: %s", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!config_path || !dump) {
        usage(argv[0]);
        return 2;
    }

    app_context_t ctx;
    if (app_context_init(&ctx, config_path) != 0) {
        return 1;
    }

    app_context_dump(&ctx);
    return 0;
}
