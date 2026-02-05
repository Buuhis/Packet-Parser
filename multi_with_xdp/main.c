#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "config.h"
#include "forwarder.h"

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format, va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [config_file]\n", prog);
}

int main(int argc, char **argv) {
    struct app_config cfg;
    struct forwarder fwd;
    const char *config_file = "config1.cfg";

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        config_file = argv[1];
    }

    libbpf_set_print(libbpf_print_silent);

    if (config_load(&cfg, config_file) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }
    config_print(&cfg);

    if (forwarder_init(&fwd, &cfg) != 0) {
        fprintf(stderr, "Failed to initialize forwarder\n");
        return 1;
    }

    forwarder_run(&fwd);
    forwarder_cleanup(&fwd);

    return 0;
}
