#define _POSIX_C_SOURCE 202405L

#include "tc.h"
#include "../utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Execute tc command */
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

int tc_add_root_qdisc(const char *ifname)
{
    if (!ifname) {
        log_error("tc_add_root_qdisc: invalid ifname");
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
    "tc qdisc del dev %s root 2>/dev/null", ifname);
    system(cmd);

    snprintf(cmd, sizeof(cmd),
        "tc qdisc add dev %s root handle 1: htb default 10",
        ifname);

    if (run_tc(cmd) != 0) {
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
        "tc class add dev %s parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit",
        ifname);

    return run_tc(cmd);
}

int tc_del_root_qdisc(const char *ifname)
{
    if (!ifname) {
        log_error("tc_del_root_qdisc: invalid ifname");
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s root",
             ifname);

    /* delete may fail if not exists → treat as OK */
    log_info("EXEC: %s", cmd);
    system(cmd);
    return 0;
}

