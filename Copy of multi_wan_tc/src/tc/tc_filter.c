#define _POSIX_C_SOURCE 202405L

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

/* Delete all filters on root (safe for re-run) */
int tc_del_filters(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc filter del dev %s parent 1:",
             ifname);
    log_info("EXEC: %s", cmd);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error executing command %s\n", cmd);
    }
    return 0;
}

int tc_add_redirect_filter(const char *ifname,
                           const char *dst_cidr,
                           int class_minor,
                           const char *out_ifname)
{
    if (!ifname || !dst_cidr || !out_ifname) {
        log_error("tc_add_redirect_filter: invalid args");
        return -1;
    }

    char cmd[512];

    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s protocol ip parent 1: prio 1 u32 "
        "match ip dst %s "
        "flowid 1:%d "
        "action mirred egress redirect dev %s",
        ifname,
        dst_cidr,
        class_minor,
        out_ifname
    );

    return run_tc(cmd);
}

