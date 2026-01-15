#define _POSIX_C_SOURCE 200809L

#include "system.h"
#include "../utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Execute ip route command safely */
static int run_ip_route(const char *action,
                        const char *cidr,
                        const char *ifname)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
             "ip route %s %s dev %s",
             action, cidr, ifname);

    log_info("EXEC: %s", cmd);

    int ret = system(cmd);
    if (ret != 0) {
        log_error("Command failed (ret=%d): %s", ret, cmd);
        return -1;
    }
    return 0;
}

int system_add_route_dev(const char *cidr, const char *ifname)
{
    if (!cidr || !ifname) {
        log_error("system_add_route_dev: invalid args");
        return -1;
    }
    return run_ip_route("replace", cidr, ifname);
}

int system_del_route_dev(const char *cidr, const char *ifname)
{
    if (!cidr || !ifname) {
        log_error("system_del_route_dev: invalid args");
        return -1;
    }
    return run_ip_route("del", cidr, ifname);
}

