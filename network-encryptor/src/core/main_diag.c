#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS: return "bypass";
    case POLICY_ACTION_ENCRYPT_L2: return "encrypt_l2";
    case POLICY_ACTION_ENCRYPT_L3: return "encrypt_l3";
    case POLICY_ACTION_ENCRYPT_L4: return "encrypt_l4";
    default: return "?";
    }
}

static const char *policy_proto_str(uint8_t proto) {
    if (proto == POLICY_PROTO_ANY)
        return "Any";
    if (proto == 6)
        return "TCP";
    if (proto == 17)
        return "UDP";
    if (proto == 1)
        return "ICMP";
    static char buf[16];
    snprintf(buf, sizeof(buf), "ip_proto=%u", (unsigned)proto);
    return buf;
}

static const char *crypto_mode_str(int mode) {
    switch (mode) {
    case CRYPTO_MODE_GCM:          return "AES-GCM";
    case CRYPTO_MODE_CTR:          return "AES-CTR";
    case CRYPTO_MODE_PQC_GCM:      return "PQC-AES-256-GCM";
    default:                       return "UNKNOWN";
    }
}

static int ipv4_netmask_to_prefix(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    int p = 0;
    while (m & 0x80000000U) {
        p++;
        m <<= 1;
    }
    return p;
}

static void ipv4_format_cidr(char *out, size_t outsz, uint32_t net_be, uint32_t mask_be) {
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = net_be };
    if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
        snprintf(out, outsz, "?");
    else
        snprintf(out, outsz, "%s/%d", ip, ipv4_netmask_to_prefix(mask_be));
}

static void policy_port_str(char *out, size_t outsz, int from, int to) {
    if (from < 0 || to < 0)
        snprintf(out, outsz, "Any");
    else if (from == to)
        snprintf(out, outsz, "%d", from);
    else
        snprintf(out, outsz, "%d-%d", from, to);
}

static void policy_cidr_field(char *out, size_t outsz, int any, int negate,
                               uint32_t net_be, uint32_t mask_be) {
    if (any) {
        snprintf(out, outsz, "Any");
        return;
    }
    char cidr[48];
    ipv4_format_cidr(cidr, sizeof(cidr), net_be, mask_be);
    if (negate)
        snprintf(out, outsz, "!%s", cidr);
    else
        snprintf(out, outsz, "%s", cidr);
}

static void log_crypto_policies_human(struct app_config *cfg, int config_id) {
    fprintf(stderr,
            "[CRYPTO POLICIES] config_id=%d — xdp_profile_crypto_policies as loaded (grouped by profile)\n",
            config_id);

    if (cfg->profile_count <= 0) {
        fprintf(stderr,
                "  (no profiles; policies=%d — check xdp_profiles / DB load)\n",
                cfg->policy_count);
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            fprintf(stderr,
                    "  [orphan POL] wire_id=%d db_id=%d %s %s proto=%s prio=%d\n",
                    cp->id,
                    cp->db_id,
                    policy_action_name(cp->action),
                    crypto_mode_str(cp->crypto_mode),
                    policy_proto_str(cp->protocol),
                    cp->priority);
        }
        return;
    }

    for (int pr = 0; pr < cfg->profile_count; pr++) {
        struct profile_config *p = &cfg->profiles[pr];
        fprintf(stderr,
                "  [profile] id=%d name=\"%s\" enabled=%d locals=%d wans=%d traffic_rules=%d policy_refs=%d\n",
                p->id,
                p->name,
                p->enabled,
                p->local_count,
                p->wan_count,
                p->traffic_rule_count,
                p->policy_count);

        if (p->local_count > 0) {
            fprintf(stderr, "    interfaces local: ");
            for (int li = 0; li < p->local_count; li++) {
                int idx = p->local_indices[li];
                if (idx >= 0 && idx < cfg->local_count) {
                    const struct local_config *lc = &cfg->locals[idx];
                    fprintf(stderr, "%s%s", li ? ", " : "", lc->ifname);
                }
            }
            fprintf(stderr, "\n");
        }
        if (p->wan_count > 0) {
            fprintf(stderr, "    interfaces wan:  ");
            for (int wi = 0; wi < p->wan_count; wi++) {
                int idx = p->wan_indices[wi];
                if (idx >= 0 && idx < cfg->wan_count) {
                    fprintf(stderr, "%s%s", wi ? ", " : "", cfg->wans[idx].ifname);
                    int bw = p->wan_bandwidth_weight[wi];
                    if (bw > 0)
                        fprintf(stderr, " [weight=%d", bw);
                    else
                        fprintf(stderr, " [equal-share");
                    fprintf(stderr, "]");
                }
            }
            fprintf(stderr, "\n");
        }

        for (int ti = 0; ti < p->traffic_rule_count; ti++) {
            struct profile_traffic_rule *tr = &p->traffic_rules[ti];
            char sbuf[64], dbuf[64];
            ipv4_format_cidr(sbuf, sizeof(sbuf), tr->src_net, tr->src_mask);
            ipv4_format_cidr(dbuf, sizeof(dbuf), tr->dst_net, tr->dst_mask);
            fprintf(stderr, "    traffic_rule[%d]: src=%s dst=%s\n", ti, sbuf, dbuf);
        }

        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char src_c[72], dst_c[72], sp[24], dp[24];
            policy_cidr_field(src_c, sizeof(src_c), cp->src_any, cp->src_negate, cp->src_net, cp->src_mask);
            policy_cidr_field(dst_c, sizeof(dst_c), cp->dst_any, cp->dst_negate, cp->dst_net, cp->dst_mask);
            policy_port_str(sp, sizeof(sp), cp->src_port_from, cp->src_port_to);
            policy_port_str(dp, sizeof(dp), cp->dst_port_from, cp->dst_port_to);

            fprintf(stderr,
                    "    crypto_policy db_id=%d wire_id=%d priority=%d\n"
                    "      layer/action: %s  |  match: protocol=%s  src_ip=%s  dst_ip=%s  src_port=%s  dst_port=%s\n"
                    "      crypto: %s-%u  nonce=%d bytes  policy_embed_byte=0x%02x (wire_id on packet for L3/L4)\n"
                    "      key_prefix(hex)=%02x%02x%02x%02x (first 4 bytes)\n",
                    cp->db_id,
                    cp->id,
                    cp->priority,
                    policy_action_name(cp->action),
                    policy_proto_str(cp->protocol),
                    src_c,
                    dst_c,
                    sp,
                    dp,
                    crypto_mode_str(cp->crypto_mode),
                    (unsigned)cp->aes_bits,
                    cp->nonce_size,
                    (unsigned)(cp->id & 0xFF),
                    cp->key[0],
                    cp->key[1],
                    cp->key[2],
                    cp->key[3]);
        }
    }
}

static void log_wan_l2_resolution_plan(struct app_config *cfg) {
    if (!cfg) return;
    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *w = &cfg->wans[i];
        fprintf(stderr,
                "[WAN CFG] if=%s peer_dst_ip=%u (ARP->dest MAC Sep) static_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                w->ifname,
                (unsigned)ntohl(w->dst_ip),
                w->dst_mac[0], w->dst_mac[1], w->dst_mac[2],
                w->dst_mac[3], w->dst_mac[4], w->dst_mac[5]);
    }
}

void main_diag_log_loaded_config(struct app_config *cfg, int config_id) {
    fprintf(stderr,
            "[DB LOAD] config_id=%d crypto_enabled=%d encrypt_layer=%d "
            "fake_protocol=%u (global xdp_configs only) "
            "crypto_mode=%d aes_bits=%d nonce_size=%d locals=%d wans=%d profiles=%d policies=%d\n",
            config_id,
            cfg->crypto_enabled,
            cfg->encrypt_layer,
            (unsigned)cfg->fake_protocol,
            cfg->crypto_mode,
            cfg->aes_bits,
            cfg->nonce_size,
            cfg->local_count,
            cfg->wan_count,
            cfg->profile_count,
            cfg->policy_count);
    log_crypto_policies_human(cfg, config_id);
    log_wan_l2_resolution_plan(cfg);
    fprintf(stderr, "[XDP REDIRECT] src_rules=%u dst_rules=%u\n",
            cfg->redirect.src_count, cfg->redirect.dst_count);
}