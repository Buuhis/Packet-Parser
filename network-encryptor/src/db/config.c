#include "../../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
int parse_mac(const char *str, uint8_t *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char ip_str[32];
    int prefix_len = 32;
    if (strchr(str, '/')) {
        if (sscanf(str, "%31[^/]/%d", ip_str, &prefix_len) != 2)
            return -1;
    } else {
        if (sscanf(str, "%31s", ip_str) != 1)
            return -1;
    }

    if (prefix_len < 0 || prefix_len > 32)
        return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (prefix_len == 0)
        *netmask = 0;
    else
        *netmask = htonl(0xFFFFFFFF << (32 - prefix_len));

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len) {
    int len = strlen(str);
    if (len != expected_len * 2)
        return -1;

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1)
            return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}


int config_validate(struct app_config *cfg) {
    if (cfg->global_frame_size == 0) {
        fprintf(stderr, "[GLOBAL] frame_size not specified\n");
        return -1;
    }

    if (cfg->global_batch_size == 0) {
        fprintf(stderr, "[GLOBAL] batch_size not specified\n");
        return -1;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
        if (local->umem_mb == 0) {
            fprintf(stderr, "LOCAL %s: umem_mb not specified\n", local->ifname);
            return -1;
        }
        if (local->ring_size == 0) {
            fprintf(stderr, "LOCAL %s: ring_size not specified\n", local->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (local->ring_size * 2 * local->frame_size) / (1024 * 1024);
        if (local->umem_mb < min_umem_mb) {
            fprintf(stderr, "LOCAL %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    local->ifname, local->umem_mb, local->ring_size, min_umem_mb);
            return -1;
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->umem_mb == 0) {
            fprintf(stderr, "WAN %s: umem_mb not specified\n", wan->ifname);
            return -1;
        }

        if (wan->ring_size == 0) {
            fprintf(stderr, "WAN %s: ring_size not specified\n", wan->ifname);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (wan->ring_size * 2 * wan->frame_size) / (1024 * 1024);
        if (wan->umem_mb < min_umem_mb) {
            fprintf(stderr, "WAN %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    wan->ifname, wan->umem_mb, wan->ring_size, min_umem_mb);
            return -1;
        }
    }

    if (cfg->profile_count > 0 && cfg->wan_count > 0) {
        int wan_owner[MAX_INTERFACES];
        for (int i = 0; i < cfg->wan_count; i++)
            wan_owner[i] = -1;

        for (int pi = 0; pi < cfg->profile_count; pi++) {
            struct profile_config *p = &cfg->profiles[pi];
            for (int wi = 0; wi < p->wan_count; wi++) {
                int idx = p->wan_indices[wi];
                if (idx < 0 || idx >= cfg->wan_count)
                    continue;
                if (wan_owner[idx] >= 0) {
                    if (wan_owner[idx] != pi) {
                        fprintf(stderr,
                                "[CONFIG] WAN \"%s\" is used by both profile \"%s\" and \"%s\"; "
                                "each WAN must belong to exactly one profile.\n",
                                cfg->wans[idx].ifname,
                                cfg->profiles[wan_owner[idx]].name,
                                p->name);
                        return -1;
                    }
                    fprintf(stderr,
                            "[CONFIG] WAN \"%s\" is listed more than once in profile \"%s\".\n",
                            cfg->wans[idx].ifname, p->name);
                    return -1;
                }
                wan_owner[idx] = pi;
            }
        }
    }

    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network) {
            return i;
        }
    }
    return -1;
}

static int cidr_match_with_negate(int any_flag, int negate,
                                    uint32_t ip, uint32_t net, uint32_t mask) {
    if (any_flag)
        return 1;
    int in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

int config_select_profile_for_flow(struct app_config *cfg, uint32_t src_ip, uint32_t dst_ip) {
    if (!cfg)
        return -1;

    for (int i = 0; i < cfg->profile_count; i++) {
        struct profile_config *p = &cfg->profiles[i];
        if (!p->enabled)
            continue;
        for (int r = 0; r < p->traffic_rule_count; r++) {
            struct profile_traffic_rule *tr = &p->traffic_rules[r];

            int forward = (src_ip & tr->src_mask) == (tr->src_net & tr->src_mask) &&
                          (dst_ip & tr->dst_mask) == (tr->dst_net & tr->dst_mask);

            int reverse = (src_ip & tr->dst_mask) == (tr->dst_net & tr->dst_mask) &&
                          (dst_ip & tr->src_mask) == (tr->src_net & tr->src_mask);
            if (forward || reverse)
                return i;
        }
    }
    return -1;
}

static uint32_t flow_hash_u32(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port ^ protocol;
    h ^= h >> 16;
    h *= 0x7feb352dU;
    h ^= h >> 15;
    h *= 0x846ca68bU;
    h ^= h >> 16;
    return h;
}

int config_select_wan_for_profile(struct app_config *cfg, int profile_idx,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t protocol) {
    if (!cfg)
        return -1;
    if (profile_idx < 0 || profile_idx >= cfg->profile_count)
        return -1;

    struct profile_config *p = &cfg->profiles[profile_idx];
    if (p->wan_count <= 0)
        return -1;

    uint32_t h = flow_hash_u32(src_ip, dst_ip, src_port, dst_port, protocol);

    int sumw = 0;
    for (int i = 0; i < p->wan_count; i++) {
        int w = p->wan_bandwidth_weight[i];
        if (w > 0)
            sumw += w;
    }

    if (sumw <= 0) {
        int slot = (int)(h % (uint32_t)p->wan_count);
        int wan_idx = p->wan_indices[slot];
        if (wan_idx < 0 || wan_idx >= cfg->wan_count)
            return -1;
        return wan_idx;
    }

    uint32_t r = h % (uint32_t)sumw;
    int acc = 0;
    for (int i = 0; i < p->wan_count; i++) {
        int w = p->wan_bandwidth_weight[i];
        if (w <= 0)
            continue;
        acc += w;
        if (r < (uint32_t)acc) {
            int wan_idx = p->wan_indices[i];
            if (wan_idx < 0 || wan_idx >= cfg->wan_count)
                return -1;
            return wan_idx;
        }
    }

    int wan_idx = p->wan_indices[p->wan_count - 1];
    if (wan_idx < 0 || wan_idx >= cfg->wan_count)
        return -1;
    return wan_idx;
}

static int crypto_policy_candidate_preferred(const struct crypto_policy *a, int a_pi,
                                             const struct crypto_policy *b, int b_pi) {
    if (!b)
        return 1;
    if (a->priority != b->priority)
        return a->priority < b->priority;
    if (a->db_id != b->db_id)
        return a->db_id < b->db_id;
    return a_pi < b_pi;
}

const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol) {
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count)
        return NULL;

    const struct profile_config *p = &cfg->profiles[profile_idx];

    for (int pass = 0; pass < 2; pass++) {
        const struct crypto_policy *best = NULL;
        int best_pi = 0;

        for (int i = 0; i < p->policy_count; i++) {
            int pi = p->policy_indices[i];
            if (pi < 0 || pi >= cfg->policy_count)
                continue;

            const struct crypto_policy *cp = &cfg->policies[pi];
            if (pass == 0) {
                if (cp->protocol == POLICY_PROTO_ANY)
                    continue;
                if (cp->protocol != protocol)
                    continue;
            } else {
                if (cp->protocol != POLICY_PROTO_ANY)
                    continue;
            }
            if (!cidr_match_with_negate(cp->src_any, cp->src_negate, src_ip, cp->src_net, cp->src_mask))
                continue;
            if (!cidr_match_with_negate(cp->dst_any, cp->dst_negate, dst_ip, cp->dst_net, cp->dst_mask))
                continue;

            if (cp->src_port_from >= 0 && cp->src_port_to >= 0) {
                if ((int)src_port < cp->src_port_from || (int)src_port > cp->src_port_to)
                    continue;
            }
            if (cp->dst_port_from >= 0 && cp->dst_port_to >= 0) {
                if ((int)dst_port < cp->dst_port_from || (int)dst_port > cp->dst_port_to)
                    continue;
            }
            if (crypto_policy_candidate_preferred(cp, pi, best, best_pi)) {
                best = cp;
                best_pi = pi;
            }
        }
        if (best)
            return best;
    }
    return NULL;
}

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}