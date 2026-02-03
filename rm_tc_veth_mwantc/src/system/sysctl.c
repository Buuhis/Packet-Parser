#define _POSIX_C_SOURCE 202405L

#include "system.h"
#include "../utils/logger.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Path used by kernel for IPv4 forwarding */
#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"

int system_get_ip_forward(void) {
    FILE *fp = fopen(IP_FORWARD_PATH, "r");
    if (!fp) {
        log_error("Failed to open %s: %s", IP_FORWARD_PATH, strerror(errno));
        return -1;
    }

    int value = -1;
    if (fscanf(fp, "%d", &value) != 1) {
        log_error("Failed to read ip_forward value");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return value;
}

static int system_set_ip_forward(int value) {
    int current = system_get_ip_forward();
    if (current < 0)
        return -1;

    if (current == value) {
        log_info("IPv4 forwarding already %s",
                 value ? "enabled" : "disabled");
        return 0;
    }

    FILE *fp = fopen(IP_FORWARD_PATH, "w");
    if (!fp) {
        log_error("Failed to open %s for writing: %s",
                  IP_FORWARD_PATH, strerror(errno));
        log_error("Are you running as root?");
        return -1;
    }

    if (fprintf(fp, "%d\n", value) < 0) {
        log_error("Failed to write ip_forward value");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    current = system_get_ip_forward();
    if (current != value) {
        log_error("IPv4 forwarding verification failed");
        return -1;
    }

    log_info("IPv4 forwarding %s successfully",
             value ? "enabled" : "disabled");
    return 0;
}

int system_enable_ip_forward(void) {
    return system_set_ip_forward(1);
}

int system_disable_ip_forward(void) {
    return system_set_ip_forward(0);
}

