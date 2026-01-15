#define _POSIX_C_SOURCE 200809L

#include "tc.h"
#include "../utils/logger.h"

#include <stdio.h>
#include <stdlib.h>

static int run_tc(const char *cmd)
{
    log_info("EXEC: %s", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        log_error("TC command failed (ret=%d): %s", ret, cmd);
        return -1;
    }
    return 0;
}

int tc_add_class(const char *ifname,
                 int parent_major,
                 int class_minor)
{
    if (!ifname) {
        log_error("tc_add_class: invalid ifname");
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "tc class add dev %s parent %d: classid %d:%d htb rate 1000mbit ceil 1000mbit",
        ifname,
        parent_major,
        parent_major,
        class_minor
    );

    return run_tc(cmd);
}

int tc_del_class(const char *ifname,
                 int parent_major,
                 int class_minor)
{
    if (!ifname) return 0;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "tc class del dev %s classid %d:%d",
        ifname,
        parent_major,
        class_minor
    );

    log_info("EXEC: %s", cmd);
    system(cmd);
    return 0;
}

