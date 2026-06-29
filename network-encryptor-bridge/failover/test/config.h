#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAX_PROFILES 16
#define MAC_LEN 6

struct wan_config {
    char ifname[IFNAMSIZ];
    uint32_t dst_ip;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    int dataplane;
};

struct profile_config {
    int wan_indices[MAX_INTERFACES];
    int wan_count;
};

struct app_config {
    struct wan_config wans[MAX_INTERFACES];
    int wan_count;
    struct profile_config profiles[MAX_PROFILES];
    int profile_count;
};

static inline int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx) {
    if (!cfg || cfg_idx < 0 || cfg_idx >= cfg->wan_count || !cfg->wans[cfg_idx].dataplane)
        return -1;
    int dp = 0;
    for (int i = 0; i < cfg_idx; i++) {
        if (cfg->wans[i].dataplane)
            dp++;
    }
    return dp;
}

static inline int config_wan_dp_to_cfg(const struct app_config *cfg, int dp_idx) {
    if (!cfg || dp_idx < 0)
        return -1;
    int dp = 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].dataplane) {
            if (dp == dp_idx)
                return i;
            dp++;
        }
    }
    return -1;
}

#endif // CONFIG_H
