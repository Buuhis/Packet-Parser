#include "tc/tc.h"
#include "utils/logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int run(const char *cmd)
{
    log_info("EXEC: %s", cmd);
    return system(cmd);
}

int tc_egress_redirect(const char *src_if,
                       const char *dst_if)
{
    char cmd[512];

    /* ensure clsact exists */
    snprintf(cmd, sizeof(cmd),
        "tc qdisc replace dev %s clsact",
        src_if);
    if (run(cmd) != 0)
        return -1;

    /* clean old egress filters */
    snprintf(cmd, sizeof(cmd),
        "tc filter del dev %s egress 2>/dev/null",
        src_if);
        if (system(cmd) != 0) {
            fprintf(stderr, "Error executing command %s\n", cmd);
        }

    /* redirect ALL traffic */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s ingress "
        "protocol ip prio 10 flower "
        "action mirred egress redirect dev %s",
        src_if, dst_if);

    return run(cmd);
}

int tc_egress_cleanup(const char *src_if)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
        "tc filter del dev %s egress 2>/dev/null",
        src_if);
        if (system(cmd) != 0) {
            fprintf(stderr, "Error executing command %s\n", cmd);
        }

    snprintf(cmd, sizeof(cmd),
        "tc qdisc del dev %s clsact 2>/dev/null",
        src_if);
        if (system(cmd) != 0) {
            fprintf(stderr, "Error executing command %s\n", cmd);
        }

    return 0;
}

