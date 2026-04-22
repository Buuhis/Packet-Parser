#include "../../inc/db_runtime.h"

#include "../../inc/db_config.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <string.h>

int run_db_check(const char *const *keywords, const char *const *values, int only_id) {
    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CHECK] DB connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    char where_buf[64] = {0};
    if (only_id >= 0)
        snprintf(where_buf, sizeof(where_buf), "WHERE c.id = %d", only_id);

    char sql[4096];
    snprintf(sql, sizeof(sql),
             "SELECT c.id, "
             "COUNT(DISTINCT p.id) AS profiles, "
             "COUNT(DISTINCT l.id) AS locals, "
             "COUNT(DISTINCT w.id) AS wans, "
             "COUNT(DISTINCT tr.id) AS traffic_rules, "
             "COUNT(DISTINCT cp.id) AS policies "
             "FROM xdp_configs c "
             "LEFT JOIN xdp_profiles p ON p.config_id = c.id "
             "LEFT JOIN xdp_local_configs l ON l.config_id = c.id "
             "LEFT JOIN xdp_wan_configs w ON w.config_id = c.id "
             "LEFT JOIN xdp_profile_traffic_rules tr ON tr.profile_id = p.id "
             "LEFT JOIN xdp_profile_crypto_policies cp ON cp.profile_id = p.id "
             "%s "
             "GROUP BY c.id "
             "ORDER BY c.id;",
             where_buf);

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] summary query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    int rows = PQntuples(res);
    if (rows == 0) {
        fprintf(stderr, "[CHECK] no config found%s\n", (only_id >= 0) ? " for requested id" : "");
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    fprintf(stdout, "[CHECK] Config summary:\n");
    for (int i = 0; i < rows; i++) {
        fprintf(stdout,
                "  id=%s profiles=%s locals=%s wans=%s traffic_rules=%s policies=%s\n",
                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5));
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT cp.id, COUNT(*) "
             "FROM xdp_profile_crypto_policies cp "
             "JOIN xdp_profiles p ON p.id = cp.profile_id "
             "JOIN xdp_configs c ON c.id = p.config_id "
             "%s "
             "GROUP BY cp.id HAVING COUNT(*) > 1 ORDER BY cp.id;",
             where_buf);
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] duplicate policy-id query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] duplicated policy IDs detected:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  policy_id=%s count=%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
    } else {
        fprintf(stdout, "[CHECK] policy-id uniqueness: OK\n");
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT cp.id, cp.aes_bits, cp.nonce_size "
             "FROM xdp_profile_crypto_policies cp "
             "JOIN xdp_profiles p ON p.id = cp.profile_id "
             "JOIN xdp_configs c ON c.id = p.config_id "
             "%s%s "
             "(cp.aes_bits NOT IN (128,256) OR cp.nonce_size < 4 OR cp.nonce_size > 16) "
             "ORDER BY cp.id;",
             where_buf,
             (where_buf[0] == '\0') ? "WHERE " : " AND ");
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] policy-params query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] invalid policy params detected:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  policy_id=%s aes_bits=%s nonce_size=%s\n",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2));
    } else {
        fprintf(stdout, "[CHECK] policy params (aes_bits/nonce_size): OK\n");
    }
    PQclear(res);
    PQfinish(conn);
    return 0;
}

static int find_local_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int find_wan_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int append_local_unique(struct app_config *dst, const struct local_config *src_loc) {
    int idx = find_local_by_ifname(dst, src_loc->ifname);
    if (idx >= 0)
        return idx;
    if (dst->local_count >= MAX_INTERFACES)
        return -1;
    dst->locals[dst->local_count] = *src_loc;
    return dst->local_count++;
}

static int append_wan_unique(struct app_config *dst, const struct wan_config *src_wan) {
    int idx = find_wan_by_ifname(dst, src_wan->ifname);
    if (idx >= 0)
        return idx;
    if (dst->wan_count >= MAX_INTERFACES)
        return -1;
    dst->wans[dst->wan_count] = *src_wan;
    return dst->wan_count++;
}

static int append_policy_unique(struct app_config *dst, const struct crypto_policy *src_cp) {
    for (int i = 0; i < dst->policy_count; i++) {
        if (dst->policies[i].id == src_cp->id)
            return i;
    }
    if (dst->policy_count >= MAX_CRYPTO_POLICIES)
        return -1;
    dst->policies[dst->policy_count] = *src_cp;
    return dst->policy_count++;
}

static void append_redirect_unique(struct app_config *dst, const struct app_config *src) {
    for (uint32_t i = 0; i < src->redirect.src_count; i++) {
        int exists = 0;
        for (uint32_t j = 0; j < dst->redirect.src_count; j++) {
            if (dst->redirect.src_net[j] == src->redirect.src_net[i] &&
                dst->redirect.src_mask[j] == src->redirect.src_mask[i]) {
                exists = 1;
                break;
            }
        }
        if (!exists && dst->redirect.src_count < MAX_SRC_NETS) {
            uint32_t k = dst->redirect.src_count++;
            dst->redirect.src_net[k] = src->redirect.src_net[i];
            dst->redirect.src_mask[k] = src->redirect.src_mask[i];
        }
    }
    for (uint32_t i = 0; i < src->redirect.dst_count; i++) {
        int exists = 0;
        for (uint32_t j = 0; j < dst->redirect.dst_count; j++) {
            if (dst->redirect.dst_net[j] == src->redirect.dst_net[i] &&
                dst->redirect.dst_mask[j] == src->redirect.dst_mask[i]) {
                exists = 1;
                break;
            }
        }
        if (!exists && dst->redirect.dst_count < MAX_DST_NETS) {
            uint32_t k = dst->redirect.dst_count++;
            dst->redirect.dst_net[k] = src->redirect.dst_net[i];
            dst->redirect.dst_mask[k] = src->redirect.dst_mask[i];
        }
    }
}

static void append_redirect_from_profiles(struct app_config *cfg) {
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled)
            continue;
        for (int ri = 0; ri < p->traffic_rule_count; ri++) {
            const struct profile_traffic_rule *tr = &p->traffic_rules[ri];

            int src_exists = 0;
            for (uint32_t i = 0; i < cfg->redirect.src_count; i++) {
                if (cfg->redirect.src_net[i] == tr->src_net &&
                    cfg->redirect.src_mask[i] == tr->src_mask) {
                    src_exists = 1;
                    break;
                }
            }
            if (!src_exists && cfg->redirect.src_count < MAX_SRC_NETS) {
                uint32_t k = cfg->redirect.src_count++;
                cfg->redirect.src_net[k] = tr->src_net;
                cfg->redirect.src_mask[k] = tr->src_mask;
            }

            int dst_exists = 0;
            for (uint32_t i = 0; i < cfg->redirect.dst_count; i++) {
                if (cfg->redirect.dst_net[i] == tr->dst_net &&
                    cfg->redirect.dst_mask[i] == tr->dst_mask) {
                    dst_exists = 1;
                    break;
                }
            }
            if (!dst_exists && cfg->redirect.dst_count < MAX_DST_NETS) {
                uint32_t k = cfg->redirect.dst_count++;
                cfg->redirect.dst_net[k] = tr->dst_net;
                cfg->redirect.dst_mask[k] = tr->dst_mask;
            }
        }
    }
}

static int merge_one_config(struct app_config *dst, const struct app_config *src) {
    int local_map[MAX_INTERFACES];
    int wan_map[MAX_INTERFACES];
    int policy_map[MAX_CRYPTO_POLICIES];
    memset(local_map, -1, sizeof(local_map));
    memset(wan_map, -1, sizeof(wan_map));
    memset(policy_map, -1, sizeof(policy_map));

    for (int i = 0; i < src->local_count; i++) {
        local_map[i] = append_local_unique(dst, &src->locals[i]);
        if (local_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->wan_count; i++) {
        wan_map[i] = append_wan_unique(dst, &src->wans[i]);
        if (wan_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->policy_count; i++) {
        policy_map[i] = append_policy_unique(dst, &src->policies[i]);
        if (policy_map[i] < 0)
            return -1;
    }

    append_redirect_unique(dst, src);

    for (int pi = 0; pi < src->profile_count; pi++) {
        if (dst->profile_count >= MAX_PROFILES)
            return -1;
        struct profile_config *dp = &dst->profiles[dst->profile_count++];
        const struct profile_config *sp = &src->profiles[pi];
        memset(dp, 0, sizeof(*dp));
        dp->id = sp->id;
        strncpy(dp->name, sp->name, sizeof(dp->name) - 1);
        dp->enabled = sp->enabled;
        dp->channel_bonding = sp->channel_bonding;

        for (int i = 0; i < sp->local_count; i++) {
            int sli = sp->local_indices[i];
            if (sli < 0 || sli >= src->local_count)
                continue;
            if (dp->local_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->local_indices[dp->local_count++] = local_map[sli];
        }
        for (int i = 0; i < sp->wan_count; i++) {
            int swi = sp->wan_indices[i];
            if (swi < 0 || swi >= src->wan_count)
                continue;
            if (dp->wan_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->wan_indices[dp->wan_count] = wan_map[swi];
            dp->wan_bandwidth_weight[dp->wan_count] = sp->wan_bandwidth_weight[i];
            dp->wan_count++;
        }
        for (int i = 0; i < sp->traffic_rule_count && i < MAX_PROFILE_TRAFFIC_RULES; i++) {
            dp->traffic_rules[i] = sp->traffic_rules[i];
            dp->traffic_rule_count++;
        }
        for (int i = 0; i < sp->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
            int spi = sp->policy_indices[i];
            if (spi < 0 || spi >= src->policy_count)
                continue;
            if (dp->policy_count >= MAX_CRYPTO_POLICIES)
                break;
            dp->policy_indices[dp->policy_count++] = policy_map[spi];
        }
    }
    return 0;
}

int build_merged_config(struct app_config *out_cfg, const int *ids, int id_count, const char *db_pass) {
    struct app_config merged;
    memset(&merged, 0, sizeof(merged));
    strncpy(merged.bpf_file, "bpf/xdp_redirect.o", sizeof(merged.bpf_file) - 1);
    merged.global_frame_size = DEFAULT_FRAME_SIZE;
    merged.global_batch_size = DEFAULT_BATCH_SIZE;

    for (int i = 0; i < id_count; i++) {
        struct app_config tmp;
        if (config_load_from_db(&tmp, ids[i], db_pass) != 0)
            return -1;
        if (merge_one_config(&merged, &tmp) != 0)
            return -1;
    }

    append_redirect_from_profiles(&merged);

    merged.crypto_enabled = (merged.policy_count > 0) ? 1 : 0;
    if (merged.crypto_enabled) {
        merged.encrypt_layer = 3;
        merged.fake_protocol = 99;
        merged.fake_ethertype_ipv4 = 0x88b5;
        merged.fake_ethertype_ipv6 = 0x88b6;
        merged.crypto_mode = merged.policies[0].crypto_mode;
        merged.aes_bits = merged.policies[0].aes_bits;
        merged.nonce_size = merged.policies[0].nonce_size;
        memcpy(merged.crypto_key, merged.policies[0].key, sizeof(merged.crypto_key));
    }

    if (config_validate(&merged) != 0)
        return -1;
    *out_cfg = merged;
    return 0;
}
