#include "../../inc/db_config.h"
#include "../../inc/packet_crypto.h"
#include "../../sig_encrypt/inc/traffic_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <strings.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../sig_encrypt/inc/pqc_handshake.h"
#include "../../sig_encrypt/inc/pqc_l2_handshake.h"

static int str_is_any(const char *v) {
    if (!v) return 1;
    while (*v == ' ' || *v == '\t') v++;
    return (v[0] == '\0' || strcasecmp(v, "any") == 0 || strcmp(v, "*") == 0);
}

static int parse_port_range(const char *v, int *from_out, int *to_out) {
    if (str_is_any(v)) {
        *from_out = -1;
        *to_out = -1;
        return 0;
    }
    int a = -1, b = -1;
    if (sscanf(v, "%d-%d", &a, &b) == 2 && a >= 0 && b >= a && b <= 65535) {
        *from_out = a;
        *to_out = b;
        return 0;
    }
    if (sscanf(v, "%d", &a) == 1 && a >= 0 && a <= 65535) {
        *from_out = a;
        *to_out = a;
        return 0;
    }
    return -1;
}

static int parse_ipv4_addr(const char *v, uint32_t *out_ip) {
    if (!v || !out_ip || v[0] == '\0')
        return -1;
    char buf[64];
    strncpy(buf, v, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;
    *out_ip = a.s_addr;
    return 0;
}

static uint8_t parse_protocol_name(const char *v) {
    if (str_is_any(v)) return POLICY_PROTO_ANY;
    if (strcasecmp(v, "tcp") == 0) return 6;
    if (strcasecmp(v, "udp") == 0) return 17;
    if (strcasecmp(v, "icmp") == 0) return 1;
    if (strcasecmp(v, "ospf") == 0) return 89;
    return (uint8_t)atoi(v);
}

static int alloc_wire_policy_id(int db_row_id, uint8_t *used) {
    if (db_row_id >= 1 && db_row_id <= 255 && !used[(size_t)db_row_id]) {
        used[(size_t)db_row_id] = 1;
        return db_row_id;
    }
    for (int j = 1; j <= 255; j++) {
        if (!used[(size_t)j]) {
            used[(size_t)j] = 1;
            if (db_row_id < 1 || db_row_id > 255)
                fprintf(stderr,
                        "[DB CRYPTO] policy db id=%d not in wire range 1..255; assigned wire id=%d\n",
                        db_row_id, j);
            else
                fprintf(stderr,
                        "[DB CRYPTO] policy db id=%d: wire id %d already in use; assigned wire id=%d\n",
                        db_row_id, db_row_id, j);
            return j;
        }
    }
    return -1;
}

static int parse_action_name(const char *v) {
    if (!v) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "bypass") == 0) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "encrypt_l2") == 0 || strcasecmp(v, "encrypt l2") == 0) return POLICY_ACTION_ENCRYPT_L2;
    if (strcasecmp(v, "encrypt_l3") == 0 || strcasecmp(v, "encrypt l3") == 0) return POLICY_ACTION_ENCRYPT_L3;
    if (strcasecmp(v, "encrypt_l4") == 0 || strcasecmp(v, "encrypt l4") == 0) return POLICY_ACTION_ENCRYPT_L4;
    return atoi(v);
}

static int parse_crypto_mode_name(const char *v) {
    if (!v || v[0] == '\0')            return CRYPTO_MODE_CTR;
    if (strcasecmp(v, "gcm") == 0)     return CRYPTO_MODE_GCM;
    if (strcasecmp(v, "ctr") == 0)     return CRYPTO_MODE_CTR;
    if (strcasecmp(v, "pqc_gcm") == 0) return CRYPTO_MODE_PQC_GCM;
    fprintf(stderr, "[DB CRYPTO] unknown crypto_mode '%s', fallback to CTR\n", v);
    return CRYPTO_MODE_CTR;
}

static int parse_cidr_any_or_negated(const char *v_in, int *any_out, int *neg_out,
                                     uint32_t *net_out, uint32_t *mask_out) {
    if (!any_out || !neg_out || !net_out || !mask_out)
        return -1;

    *any_out = 1;
    *neg_out = 0;
    *net_out = 0;
    *mask_out = 0;

    if (str_is_any(v_in)) {
        *any_out = 1;
        return 0;
    }


    while (*v_in == ' ' || *v_in == '\t') v_in++;
    if (v_in[0] == '!') {
        *neg_out = 1;
        v_in++;
        while (*v_in == ' ' || *v_in == '\t') v_in++;
    }

    uint32_t ip = 0, mask = 0, net = 0;
    if (parse_ip_cidr_pub(v_in, &ip, &mask, &net) != 0) {
        return -1;
    }
    *any_out = 0;
    *net_out = net;
    *mask_out = mask;
    return 0;
}

static void trim_spaces_inplace(char *s) {
    if (!s)
        return;
    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && (s[start] == ' ' || s[start] == '\t'))
        start++;
    size_t end = len;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    if (start > 0 && end > start)
        memmove(s, s + start, end - start);
    if (end <= start) {
        s[0] = '\0';
        return;
    }
    s[end - start] = '\0';
}

#define MAX_CIDR_LIST_ITEMS 32
#define MAX_CIDR_ITEM_LEN 64

static int split_cidr_list(const char *input, char out[][MAX_CIDR_ITEM_LEN], int max_out) {
    if (!input || !out || max_out <= 0)
        return -1;

    char buf[1024];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim_spaces_inplace(buf);
    if (buf[0] == '\0')
        return -1;

    int count = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        if (count >= max_out)
            return -1;
        trim_spaces_inplace(tok);
        if (tok[0] == '\0')
            return -1;
        strncpy(out[count], tok, MAX_CIDR_ITEM_LEN - 1);
        out[count][MAX_CIDR_ITEM_LEN - 1] = '\0';
        count++;
    }
    return (count > 0) ? count : -1;
}

static int find_local_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static int find_wan_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static int load_profiles_and_policies(struct app_config *cfg, PGconn *conn, int config_id) {
    // Unconditionally scan and load any newly generated keys from RAM-disk (/dev/shm) into registry
    sig_pqc_load_keys_from_disk();

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT id, profile_name, enabled, channel_bonding, local_identity_fingerprint "
        "FROM xdp_profiles WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {

        PQclear(res);
        return 0;
    }

    int nprof = PQntuples(res);
    if (nprof > MAX_PROFILES) nprof = MAX_PROFILES;

    for (int i = 0; i < nprof; i++) {
        struct profile_config *p = &cfg->profiles[cfg->profile_count];
        memset(p, 0, sizeof(*p));
        p->id = atoi(PQgetvalue(res, i, 0));
        strncpy(p->name, PQgetvalue(res, i, 1), sizeof(p->name) - 1);
        p->enabled = atoi(PQgetvalue(res, i, 2));
        p->channel_bonding = atoi(PQgetvalue(res, i, 3));
        if (!PQgetisnull(res, i, 4)) {
            strncpy(p->local_identity_fingerprint, PQgetvalue(res, i, 4), sizeof(p->local_identity_fingerprint) - 1);
        } else {
            p->local_identity_fingerprint[0] = '\0';
        }
        cfg->profile_count++;
    }
    PQclear(res);

    uint8_t wire_id_used[256];
    memset(wire_id_used, 0, sizeof(wire_id_used));
    wire_id_used[0] = 1;
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        struct profile_config *p = &cfg->profiles[pi];

        char profile_id_str[32];
        snprintf(profile_id_str, sizeof(profile_id_str), "%d", p->id);
        const char *pp[1] = { profile_id_str };

        res = PQexecParams(conn,
            "SELECT ifname FROM xdp_profile_locals WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->local_count < MAX_PROFILE_INTERFACES; r++) {
                const char *ifname = PQgetvalue(res, r, 0);
                int li = find_local_index_by_ifname(cfg, ifname);
                if (li >= 0) p->local_indices[p->local_count++] = li;
            }
        }
        PQclear(res);

        res = PQexecParams(conn,
            "SELECT ifname, bandwidth_weight_percent FROM xdp_profile_wans WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int wcol = PQfnumber(res, "bandwidth_weight_percent");
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->wan_count < MAX_PROFILE_INTERFACES; r++) {
                const char *ifname = PQgetvalue(res, r, 0);
                int wi = find_wan_index_by_ifname(cfg, ifname);
                if (wi >= 0) {
                    p->wan_indices[p->wan_count] = wi;
                    if (wcol >= 0)
                        p->wan_bandwidth_weight[p->wan_count] = atoi(PQgetvalue(res, r, wcol));
                    else
                        p->wan_bandwidth_weight[p->wan_count] = 0;
                    p->wan_count++;
                }
            }
        }
        PQclear(res);

        res = PQexecParams(conn,
            "SELECT src_cidr, dst_cidr FROM xdp_profile_traffic_rules WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->traffic_rule_count < MAX_PROFILE_TRAFFIC_RULES; r++) {
                struct profile_traffic_rule *tr = &p->traffic_rules[p->traffic_rule_count];
                uint32_t sip = 0, smask = 0, snet = 0;
                uint32_t dip = 0, dmask = 0, dnet = 0;
                const char *src = PQgetvalue(res, r, 0);
                const char *dst = PQgetvalue(res, r, 1);
                if (parse_ip_cidr_pub(src, &sip, &smask, &snet) != 0 ||
                    parse_ip_cidr_pub(dst, &dip, &dmask, &dnet) != 0) {
                    continue;
                }
                tr->src_net = snet;
                tr->src_mask = smask;
                tr->dst_net = dnet;
                tr->dst_mask = dmask;
                p->traffic_rule_count++;
            }
        }
        PQclear(res);



        res = PQexecParams(conn,
            "SELECT id, priority, action, protocol, crypto_mode, aes_bits, nonce_size, crypto_key "
            "FROM xdp_profile_crypto_policies WHERE profile_id = $1 "
            "ORDER BY priority ASC, id ASC",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows; r++) {
                struct crypto_policy cp_base;
                memset(&cp_base, 0, sizeof(cp_base));

                int db_policy_id = atoi(PQgetvalue(res, r, 0));
                if (db_policy_id < 0) {
                    fprintf(stderr,
                            "[DB CRYPTO] policy id=%d is invalid (expected >= 0)\n",
                            db_policy_id);
                    PQclear(res);
                    return -1;
                }
                int wire_id = alloc_wire_policy_id(db_policy_id, wire_id_used);
                if (wire_id < 0) {
                    fprintf(stderr, "[DB CRYPTO] no free wire policy id (max 255 policies)\n");
                    PQclear(res);
                    return -1;
                }
                cp_base.id = wire_id;
                cp_base.db_id = db_policy_id;
                cp_base.priority = atoi(PQgetvalue(res, r, 1));
                cp_base.action = parse_action_name(PQgetvalue(res, r, 2));
                cp_base.protocol = parse_protocol_name(PQgetvalue(res, r, 3));

                const char *mode = PQgetvalue(res, r, 4);
                const char *bits = PQgetvalue(res, r, 5);
                const char *nonce = PQgetvalue(res, r, 6);
                const char *key_hex = PQgetvalue(res, r, 7);

                cp_base.crypto_mode = parse_crypto_mode_name(mode);
                cp_base.aes_bits = bits ? atoi(bits) : 128;
                cp_base.nonce_size = nonce ? atoi(nonce) : 12;
                if (cp_base.aes_bits != 128 && cp_base.aes_bits != 256) {
                    fprintf(stderr,
                            "[DB CRYPTO] policy id=%d has invalid aes_bits=%d (allowed: 128,256)\n",
                            cp_base.id, cp_base.aes_bits);
                    PQclear(res);
                    return -1;
                }
                if (cp_base.nonce_size < 4 || cp_base.nonce_size > 16) {
                    fprintf(stderr,
                            "[DB CRYPTO] policy id=%d has invalid nonce_size=%d (allowed: 4..16)\n",
                            cp_base.id, cp_base.nonce_size);
                    PQclear(res);
                    return -1;
                }

                if (key_hex && key_hex[0] != '\0') {
                    int key_len = (cp_base.aes_bits == 256) ? 32 : 16;
                    if (parse_hex_bytes_pub(key_hex, cp_base.key, key_len) != 0) {
                        memset(cp_base.key, 0, sizeof(cp_base.key));
                    }
                }

                if (cp_base.crypto_mode == CRYPTO_MODE_PQC_GCM) {
                    sig_pqc_load_and_bind_policy(conn, cfg, pi, db_policy_id, p->id);
                }


                char policy_id_str[32];
                snprintf(policy_id_str, sizeof(policy_id_str), "%d", db_policy_id);
                const char *pm[1] = { policy_id_str };
                PGresult *mres = PQexecParams(conn,
                    "SELECT src_cidr, src_port, dst_cidr, dst_port "
                    "FROM xdp_profile_crypto_policy_matches WHERE policy_id = $1 ORDER BY id",
                    1, NULL, pm, NULL, NULL, 0);

                int match_rows = 0;
                if (PQresultStatus(mres) != PGRES_TUPLES_OK) {
                    fprintf(stderr,
                            "[DB CRYPTO] policy id=%d failed to read xdp_profile_crypto_policy_matches: %s",
                            cp_base.id,
                            PQresultErrorMessage(mres));
                    PQclear(mres);
                    PQclear(res);
                    return -1;
                }
                match_rows = PQntuples(mres);
                if (match_rows <= 0) {
                    fprintf(stderr,
                            "[DB CRYPTO] policy id=%d has no rows in xdp_profile_crypto_policy_matches (required)\n",
                            cp_base.id);
                    PQclear(mres);
                    PQclear(res);
                    return -1;
                }

                for (int mr = 0; mr < match_rows; mr++) {
                    const char *src_cidr = PQgetvalue(mres, mr, 0);
                    const char *src_port = PQgetvalue(mres, mr, 1);
                    const char *dst_cidr = PQgetvalue(mres, mr, 2);
                    const char *dst_port = PQgetvalue(mres, mr, 3);

                    struct crypto_policy cp_match = cp_base;
                    if (parse_port_range(src_port, &cp_match.src_port_from, &cp_match.src_port_to) != 0) {
                        cp_match.src_port_from = -1;
                        cp_match.src_port_to = -1;
                    }
                    if (parse_port_range(dst_port, &cp_match.dst_port_from, &cp_match.dst_port_to) != 0) {
                        cp_match.dst_port_from = -1;
                        cp_match.dst_port_to = -1;
                    }

                    char src_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];
                    char dst_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];
                    int src_n = split_cidr_list(src_cidr, src_items, MAX_CIDR_LIST_ITEMS);
                    int dst_n = split_cidr_list(dst_cidr, dst_items, MAX_CIDR_LIST_ITEMS);
                    if (src_n <= 0 || dst_n <= 0) {
                        fprintf(stderr,
                                "[DB CRYPTO] policy id=%d has invalid CIDR list src_cidr=%s dst_cidr=%s\n",
                                cp_base.id,
                                src_cidr ? src_cidr : "(null)",
                                dst_cidr ? dst_cidr : "(null)");
                        PQclear(mres);
                        PQclear(res);
                        return -1;
                    }

                    for (int si = 0; si < src_n; si++) {
                        for (int di = 0; di < dst_n; di++) {
                            if (cfg->policy_count >= MAX_CRYPTO_POLICIES || p->policy_count >= MAX_CRYPTO_POLICIES) {
                                fprintf(stderr,
                                        "[DB CRYPTO] policy expansion overflow for policy id=%d (MAX_CRYPTO_POLICIES=%d)\n",
                                        cp_base.id, MAX_CRYPTO_POLICIES);
                                PQclear(mres);
                                PQclear(res);
                                return -1;
                            }

                            struct crypto_policy *cp = &cfg->policies[cfg->policy_count];
                            *cp = cp_match;
                            cp->profile_id = p->id;

                            if (parse_cidr_any_or_negated(src_items[si], &cp->src_any, &cp->src_negate,
                                                          &cp->src_net, &cp->src_mask) != 0) {
                                fprintf(stderr, "[DB CRYPTO] policy id=%d has invalid src_cidr item=%s\n",
                                        cp->id, src_items[si]);
                                PQclear(mres);
                                PQclear(res);
                                return -1;
                            }
                            if (parse_cidr_any_or_negated(dst_items[di], &cp->dst_any, &cp->dst_negate,
                                                          &cp->dst_net, &cp->dst_mask) != 0) {
                                fprintf(stderr, "[DB CRYPTO] policy id=%d has invalid dst_cidr item=%s\n",
                                        cp->id, dst_items[di]);
                                PQclear(mres);
                                PQclear(res);
                                return -1;
                            }

                            p->policy_indices[p->policy_count++] = cfg->policy_count;
                            cfg->policy_count++;
                        }
                    }
                }
                PQclear(mres);
            }
        } else {
            fprintf(stderr, "[DB CRYPTO] failed to read xdp_profile_crypto_policies: %s\n", PQresultErrorMessage(res));
            PQclear(res);
            return -1;
        }
    }

    return 0;
}

static int load_local_rows(struct app_config *cfg, PGresult *res)
{
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No LOCAL interface defined for this config\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many LOCAL interfaces (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct local_config *loc = &cfg->locals[cfg->local_count];
        memset(loc, 0, sizeof(*loc));

        loc->frame_size  = cfg->global_frame_size;
        loc->batch_size  = cfg->global_batch_size;
        loc->umem_mb     = DEFAULT_UMEM_MB_LOCAL;
        loc->ring_size   = DEFAULT_RING_SIZE;
        loc->queue_count = DEFAULT_QUEUE_COUNT;

        const char *v;

        v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB LOCAL][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(loc->ifname, v, IF_NAMESIZE - 1);

        v = PQgetvalue(res, row, PQfnumber(res, "network"));
        if (v && v[0] != '\0') {
            if (parse_ip_cidr_pub(v, &loc->ip, &loc->netmask, &loc->network) != 0) {
                fprintf(stderr, "[DB LOCAL] Invalid network CIDR: %s\n", v);
                return -1;
            }
        }

        cfg->local_count++;
    }
    return 0;
}

static int load_wan_rows(struct app_config *cfg, PGresult *res)
{
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No WAN interface defined for this config\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many WAN interfaces (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct wan_config *wan = &cfg->wans[cfg->wan_count];
        memset(wan, 0, sizeof(*wan));

        wan->frame_size   = cfg->global_frame_size;
        wan->batch_size   = cfg->global_batch_size;
        wan->window_size  = (uint32_t)(WAN_REORDER_WINDOW_KB * 1024U);
        wan->umem_mb      = DEFAULT_UMEM_MB_WAN;
        wan->ring_size    = DEFAULT_RING_SIZE_WAN;
        wan->queue_count  = DEFAULT_QUEUE_COUNT;

        const char *v;

        v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB WAN][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(wan->ifname, v, IF_NAMESIZE - 1);

        int dst_ip_col = PQfnumber(res, "dst_ip");
        if (dst_ip_col >= 0) {
            v = PQgetvalue(res, row, dst_ip_col);
            if (v && v[0] != '\0' && parse_ipv4_addr(v, &wan->dst_ip) != 0) {
                fprintf(stderr, "[DB WAN] Invalid dst_ip: %s\n", v);
                return -1;
            }
        }


        int src_mac_col = PQfnumber(res, "src_mac");
        int dst_mac_col = PQfnumber(res, "dst_mac");
        if (src_mac_col >= 0) {
            v = PQgetvalue(res, row, src_mac_col);
            if (v && v[0] != '\0' && parse_mac(v, wan->src_mac) != 0) {
                fprintf(stderr, "[DB WAN] Invalid src_mac: %s\n", v);
                return -1;
            }
        }
        if (dst_mac_col >= 0) {
            v = PQgetvalue(res, row, dst_mac_col);
            if (v && v[0] != '\0' && parse_mac(v, wan->dst_mac) != 0) {
                fprintf(stderr, "[DB WAN] Invalid dst_mac: %s\n", v);
                return -1;
            }
        }


        cfg->wan_count++;
    }
    return 0;
}


static int load_redirect_rules(struct app_config *cfg, PGconn *conn, int config_id)
{
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT src_cidr, dst_cidr "
        "FROM xdp_redirect_rules WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Query xdp_redirect_rules failed: %s\n",
                PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    int nrows = PQntuples(res);
    cfg->redirect.src_count = 0;
    cfg->redirect.dst_count = 0;

    for (int i = 0; i < nrows; i++) {
        const char *src = PQgetvalue(res, i, 0);
        const char *dst = PQgetvalue(res, i, 1);

        uint32_t sip, smask, snet;
        uint32_t dip, dmask, dnet;

        if (parse_ip_cidr_pub(src, &sip, &smask, &snet) != 0 ||
            parse_ip_cidr_pub(dst, &dip, &dmask, &dnet) != 0) {
            fprintf(stderr, "[DB] Invalid redirect CIDR: %s -> %s\n", src, dst);
            PQclear(res);
            return -1;
        }

        if (cfg->redirect.src_count < MAX_SRC_NETS) {
            int si = cfg->redirect.src_count++;
            cfg->redirect.src_net[si]  = snet;
            cfg->redirect.src_mask[si] = smask;
        }

        if (cfg->redirect.dst_count < MAX_DST_NETS) {
            int di = cfg->redirect.dst_count++;
            cfg->redirect.dst_net[di]  = dnet;
            cfg->redirect.dst_mask[di] = dmask;
        }
    }

    PQclear(res);
    return 0;
}

static int db_verify_config_id(PGconn *conn, int config_id)
{
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT 1 FROM xdp_configs WHERE id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Query xdp_configs failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }
    if (PQntuples(res) == 0) {
        fprintf(stderr, "[DB] Config ID %d not found in xdp_configs\n", config_id);
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int db_load_local_configs(PGconn *conn, struct app_config *cfg, int config_id)
{
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT ifname, network "
        "FROM xdp_local_configs WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        res = PQexecParams(conn,
            "SELECT ifname, network "
            "FROM xdp_local_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Query xdp_local_configs failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    if (load_local_rows(cfg, res) != 0) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int db_load_wan_configs(PGconn *conn, struct app_config *cfg, int config_id)
{
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT ifname, dst_ip "
        "FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        res = PQexecParams(conn,
            "SELECT ifname, dst_ip, src_mac, dst_mac "
            "FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        res = PQexecParams(conn,
            "SELECT ifname FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Query xdp_wan_configs failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    if (load_wan_rows(cfg, res) != 0) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int apply_crypto_derived_from_policies(struct app_config *cfg)
{
    cfg->crypto_enabled = 0;
    cfg->encrypt_layer = 0;
    cfg->fake_protocol = 0;
    cfg->fake_ethertype_ipv4 = 0;
    cfg->fake_ethertype_ipv6 = 0;
    cfg->crypto_mode = CRYPTO_MODE_CTR;
    cfg->aes_bits = 128;
    cfg->nonce_size = 12;
    memset(cfg->crypto_key, 0, sizeof(cfg->crypto_key));

    if (cfg->policy_count <= 0)
        return 0;

    int has_l2 = 0, has_l3 = 0, has_l4 = 0;
    int first_key_pi = -1;

    int has_pqc = 0;
    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp) continue;
        if (cp->action == POLICY_ACTION_ENCRYPT_L2) has_l2 = 1;
        else if (cp->action == POLICY_ACTION_ENCRYPT_L3) has_l3 = 1;
        else if (cp->action == POLICY_ACTION_ENCRYPT_L4) has_l4 = 1;

        if (cp->crypto_mode == CRYPTO_MODE_PQC_GCM) {
            has_pqc = 1;
        }

        if (cp->action != POLICY_ACTION_BYPASS) {
            int nonzero = 0;
            for (int k = 0; k < AES_KEY_LEN; k++) {
                if (cp->key[k] != 0) { nonzero = 1; break; }
            }
            if (nonzero && first_key_pi < 0)
                first_key_pi = pi;
        }
    }

    cfg->crypto_enabled = (has_l2 || has_l3 || has_l4) ? 1 : 0;
    if (cfg->crypto_enabled) {
        if (has_l2) cfg->encrypt_layer = 2;
        else if (has_l3) cfg->encrypt_layer = 3;
        else if (has_l4) cfg->encrypt_layer = 4;
    }

    if (cfg->crypto_enabled) {
        if (first_key_pi < 0) {
            if (has_pqc) {
                // For PQC-GCM, static DB key is optional since it is negotiated dynamically via Handshake
                cfg->crypto_mode = CRYPTO_MODE_PQC_GCM;
                cfg->aes_bits = 256;
                cfg->nonce_size = 12;
                memset(cfg->crypto_key, 0, sizeof(cfg->crypto_key));
            } else {
                fprintf(stderr,
                        "[DB CRYPTO] policies request encryption but no crypto_key was provided in xdp_profile_crypto_policies\n");
                return -1;
            }
        } else {
            const struct crypto_policy *cp = &cfg->policies[first_key_pi];
            cfg->crypto_mode = cp->crypto_mode;
            cfg->aes_bits = (cp->aes_bits == 256) ? 256 : 128;
            cfg->nonce_size = (cp->nonce_size > 0) ? cp->nonce_size : 12;
            memcpy(cfg->crypto_key, cp->key, sizeof(cfg->crypto_key));
        }
    }

    if (has_l3 || has_l4) {
        cfg->fake_protocol = 99;
    }
    if (has_l2) {
        cfg->fake_ethertype_ipv4 = 0x88b5;
        cfg->fake_ethertype_ipv6 = 0x88b6;
    }

    if (cfg->crypto_enabled) {
        const char *mode_str = "UNKNOWN";
        if (cfg->crypto_mode == CRYPTO_MODE_GCM) mode_str = "GCM";
        else if (cfg->crypto_mode == CRYPTO_MODE_CTR) mode_str = "CTR";
        else if (cfg->crypto_mode == CRYPTO_MODE_PQC_GCM) mode_str = "PQC-GCM";

        fprintf(stderr, "[DB CRYPTO] Policies loaded successfully! Crypto: ENABLED, Layer: %d, Mode: %s, AES: %d-bits, Nonce: %d bytes\n",
                cfg->encrypt_layer, mode_str, cfg->aes_bits, cfg->nonce_size);
    } else {
        fprintf(stderr, "[DB CRYPTO] Policies loaded: Crypto is DISABLED\n");
    }

    return 0;
}


static int fetch_config_from_db(struct app_config *cfg, PGconn *conn, int config_id)
{
    if (db_verify_config_id(conn, config_id) != 0)
        return -1;
    if (db_load_local_configs(conn, cfg, config_id) != 0)
        return -1;
    if (load_redirect_rules(cfg, conn, config_id) != 0)
        return -1;
    if (db_load_wan_configs(conn, cfg, config_id) != 0)
        return -1;
    if (load_profiles_and_policies(cfg, conn, config_id) != 0)
        return -1;
    return 0;
}

int db_check_identities(const char *conn_str) {
    (void)conn_str;
    const char *db_host = getenv("POSTGRES_HOST");
    const char *db_port = getenv("POSTGRES_PORT");
    const char *db_user = getenv("POSTGRES_USER");
    const char *db_name = getenv("POSTGRES_TABLE");
    const char *db_pass = getenv("DB_PASS");

    if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
        fprintf(stderr, "[DB] Missing DB_* environment variables in db_check_identities\n");
        return -1;
    }

    const char *keywords[] = {
        "host", "port", "dbname", "user", "password", "connect_timeout", NULL,
    };
    const char *values[] = {
        db_host, db_port, db_name, db_user, db_pass, "10", NULL,
    };

    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    printf("\n=== PQC IDENTITY INTEGRITY CHECK ===\n");
    sig_pqc_load_keys_from_disk();

    PGresult *p_res = PQexec(conn, 
        "SELECT c.id AS policy_id, p.profile_name, i.local_identity_fingerprint, i.peer_pub "
        "FROM xdp_profile_crypto_policies c "
        "JOIN xdp_profiles p ON c.profile_id = p.id "
        "LEFT JOIN pqc_identities i ON c.id = i.policy_id "
        "WHERE c.crypto_mode = 'pqc-gcm' "
        "ORDER BY c.id");

    if (PQresultStatus(p_res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Failed to query policies: %s\n", PQerrorMessage(conn));
        PQclear(p_res);
        PQfinish(conn);
        return -1;
    }

    int n_policies = PQntuples(p_res);
    for (int i = 0; i < n_policies; i++) {
        int policy_id = atoi(PQgetvalue(p_res, i, 0));
        const char *pname = PQgetvalue(p_res, i, 1);
        const char *local_fg = PQgetvalue(p_res, i, 2);
        const char *peer_pub_path = PQgetvalue(p_res, i, 3);

        printf("Policy ID: %d (Profile: %s)\n", policy_id, pname);

        char *found_priv = NULL;
        char *found_pub = NULL;
        if (local_fg && strlen(local_fg) > 0) {
            printf("  - Local Key Fingerprint: [%s]\n", local_fg);
            sig_pqc_find_identity(local_fg, &found_priv, &found_pub);
            if (found_priv) {
                printf("    -> Found matching local ML-DSA key in RAM Registry.\n");
            } else {
                printf("    -> Warning: Local ML-DSA key NOT found in RAM Registry.\n");
            }
        } else {
            printf("  - Local Key Fingerprint: NOT ASSIGNED\n");
        }

        if (peer_pub_path && strlen(peer_pub_path) > 0) {
            printf("  - Peer Public Key: PATH [%s]\n", peer_pub_path);
            FILE *fp = fopen(peer_pub_path, "r");
            if (fp) {
                char file_content[128];
                memset(file_content, 0, sizeof(file_content));
                if (fgets(file_content, sizeof(file_content) - 1, fp) != NULL) {
                    file_content[strcspn(file_content, "\r\n")] = '\0';
                    if (strlen(file_content) >= 8) {
                        char peer_fg[16];
                        strncpy(peer_fg, file_content, 8);
                        peer_fg[8] = '\0';
                        printf("  - Peer Key Fingerprint: [%s] (loaded from file)\n", peer_fg);
                    } else {
                        printf("  - Peer Key Fingerprint: INVALID FORMAT (too short)\n");
                    }
                } else {
                    printf("  - Peer Key Fingerprint: EMPTY FILE\n");
                }
                fclose(fp);
            } else {
                printf("  - Peer Key Fingerprint: ERROR (could not read file [%s])\n", peer_pub_path);
            }
        } else {
            printf("  - Peer Public Key: EMPTY / NOT ASSIGNED in pqc_identities\n");
        }

        printf("  - Role Configured: [DYNAMIC (resolved at runtime)]\n");
        printf("\n");
    }

    PQclear(p_res);
    PQfinish(conn);
    printf("=== END OF INTEGRITY CHECK ===\n\n");
    return 0;
}

int config_load_from_db(struct app_config *cfg, int config_id, const char *conn_str)
{
    (void)conn_str;

    if (!cfg) {
        fprintf(stderr, "[DB] Null pointer argument (cfg)\n");
        return -1;
    }

    const char *db_host = getenv("POSTGRES_HOST");
    const char *db_port = getenv("POSTGRES_PORT");
    const char *db_user = getenv("POSTGRES_USER");
    const char *db_name = getenv("POSTGRES_TABLE");
    const char *db_pass = getenv("DB_PASS");

    if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
        fprintf(stderr, "[DB] Missing DB_* environment variables in config_load_from_db\n");
        return -1;
    }

    const char *keywords[] = {
        "host", "port", "dbname", "user", "password", "connect_timeout", NULL,
    };
    const char *values[] = {
        db_host, db_port, db_name, db_user, db_pass, "10", NULL,
    };

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);
    cfg->global_frame_size = DEFAULT_FRAME_SIZE;
    cfg->global_batch_size = DEFAULT_BATCH_SIZE;

    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    if (fetch_config_from_db(cfg, conn, config_id) != 0) {
        PQfinish(conn);
        return -1;
    }

    PQfinish(conn);

    if (apply_crypto_derived_from_policies(cfg) != 0)
        return -1;

    return config_validate(cfg);
}