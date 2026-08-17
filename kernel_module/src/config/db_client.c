#include "db_client.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

PGconn *g_db_conn = NULL;
pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Convert hex string to binary bytes. Returns number of bytes written, or -1 on error. */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len)
{
    if (!hex || !out) return -1;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;  /* Must be even */
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + (i * 2), "%2x", &byte_val) != 1) return -1;
        out[i] = (uint8_t)byte_val;
    }
    return (int)byte_len;
}

static bool pg_bool(PGresult *res, int row, int col)
{
    return !PQgetisnull(res, row, col) &&
           strcmp(PQgetvalue(res, row, col), "t") == 0;
}

static int copy_pg_field(PGresult *res, int row, int col, char *dst,
                         size_t dst_len, bool required,
                         const char *field_name)
{
    int value_len;

    if (!dst || dst_len == 0)
        return -1;
    dst[0] = '\0';
    if (PQgetisnull(res, row, col)) {
        if (required)
            log_error("Required DB field %s is NULL", field_name);
        return required ? -1 : 0;
    }

    value_len = PQgetlength(res, row, col);
    if (value_len <= 0 && required) {
        log_error("Required DB field %s is empty", field_name);
        return -1;
    }
    if ((size_t)value_len >= dst_len) {
        log_error("DB field %s is too long (%d bytes, max %zu)",
                  field_name, value_len, dst_len - 1);
        return -1;
    }

    memcpy(dst, PQgetvalue(res, row, col), (size_t)value_len);
    dst[value_len] = '\0';
    return 0;
}

/* Column order must match the sdwan_tunnels SELECT statements below. */
static int parse_tunnel_row(PGresult *res, int row, bool weight_enabled,
                            sdwan_tun_cfg_t *tun)
{
    int configured_weight;

    memset(tun, 0, sizeof(*tun));
    if (copy_pg_field(res, row, 0, tun->tunnel_ifname,
                      sizeof(tun->tunnel_ifname), true,
                      "sdwan_tunnels.tunnel_name") < 0 ||
        copy_pg_field(res, row, 1, tun->physical_ifname,
                      sizeof(tun->physical_ifname), true,
                      "interfaces.interface") < 0 ||
        copy_pg_field(res, row, 2, tun->tunnel_ip,
                      sizeof(tun->tunnel_ip), false,
                      "sdwan_tunnels.ip_addr") < 0 ||
        copy_pg_field(res, row, 5, tun->latency_ip,
                      sizeof(tun->latency_ip), false,
                      "sdwan_tunnels.latency_ip") < 0 ||
        copy_pg_field(res, row, 8, tun->loss_ip,
                      sizeof(tun->loss_ip), false,
                      "sdwan_tunnels.loss_ip") < 0)
        return -1;

    tun->segment_id = PQgetisnull(res, row, 3) ? 0 :
                      atoi(PQgetvalue(res, row, 3));
    configured_weight = PQgetisnull(res, row, 4) ? 1 :
                        atoi(PQgetvalue(res, row, 4));
    if (weight_enabled && configured_weight <= 0) {
        log_error("Tunnel %s has invalid weight %d",
                  tun->tunnel_ifname, configured_weight);
        return -1;
    }
    tun->weight = weight_enabled ? configured_weight : 1;
    tun->latency = PQgetisnull(res, row, 6) ? 0 :
                   atoi(PQgetvalue(res, row, 6));
    tun->latency_enabled = pg_bool(res, row, 7);
    tun->loss_percentage = PQgetisnull(res, row, 9) ? 0 :
                           atoi(PQgetvalue(res, row, 9));
    tun->loss_enabled = pg_bool(res, row, 10);
    return 0;
}

int db_client_connect(const char *host, const char *port, const char *user, const char *dbname, const char *password)
{
    const char *keywords[] = {"host", "port", "user", "dbname", "password", "connect_timeout", NULL};
    const char *values[]   = {host, port, user, dbname, password, "10", NULL};

    g_db_conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(g_db_conn) != CONNECTION_OK) {
        log_error("Connection to database failed: %s", PQerrorMessage(g_db_conn));
        PQfinish(g_db_conn);
        g_db_conn = NULL;
        return -1;
    }
    return 0;
}

void db_client_disconnect(void)
{
    if (g_db_conn) {
        PQfinish(g_db_conn);
        g_db_conn = NULL;
    }
}

int db_client_load_config(int profile_id, app_config_t *cfg)
{
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        log_error("Database connection is not open.");
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    /* 1. Fetch sdwan_profiles info by profile_id */
    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *paramValues[1] = { id_str };
    
    PGresult *res = PQexecParams(g_db_conn,
        "SELECT action, method, encryption_key, weight_enable, latency_enable, loss_enable, latency_duration, loss_duration "
        "FROM public.sdwan_profiles WHERE id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT sdwan_profiles failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    if (PQntuples(res) == 0) {
        log_error("No sdwan_profile found with id '%d'", profile_id);
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    memset(cfg, 0, sizeof(*cfg));
    cfg->node_id = profile_id;
    
    const char *action      = PQgetvalue(res, 0, 0);
    const char *method      = PQgetvalue(res, 0, 1);
    const char *enc_key_hex = PQgetvalue(res, 0, 2);

    cfg->weight_enabled = pg_bool(res, 0, 3);
    cfg->latency_enabled = pg_bool(res, 0, 4);
    cfg->loss_enabled = pg_bool(res, 0, 5);
    cfg->latency_duration = PQgetisnull(res, 0, 6) ? 0 :
                            atoi(PQgetvalue(res, 0, 6));
    cfg->loss_duration = PQgetisnull(res, 0, 7) ? 0 :
                         atoi(PQgetvalue(res, 0, 7));
    
    cfg->encrypt.enabled = (method && strcmp(method, "None") != 0);
    
    if (cfg->encrypt.enabled) {
        /* Layer mode: '2' -> L2 (PQC), '3' -> L3 (Overlay) */
        cfg->encrypt.layer = (action && strcmp(action, "2") == 0) ? 2 : 3;

        /* Map string method to enum */
        if (method && strcmp(method, "aes-gcm-256") == 0) {
            cfg->encrypt.type = 1;  /* MWAN_CRYPT_AES_GCM_256 */
        } else if (method && strcmp(method, "pqc-gcm") == 0) {
            cfg->encrypt.type = 2;  /* MWAN_CRYPT_PQC_GCM */
        } else {
            cfg->encrypt.type = 0;  /* MWAN_CRYPT_AES_GCM_128 */
        }
        
        /* Convert static hex key if present */
        if (enc_key_hex && strlen(enc_key_hex) > 0) {
            int klen = hex_to_bytes(enc_key_hex, cfg->encrypt.key, MAX_ENCRYPT_KEY_LEN);
            if (klen > 0) {
                cfg->encrypt.key_len = (size_t)klen;
            }
        }
    }
    PQclear(res);
    
    /* 2. Fetch sdwan_tunnels JOIN interfaces info */
    res = PQexecParams(g_db_conn,
        "SELECT t.tunnel_name, i.interface, t.ip_addr, t.segment_id, t.weight, "
        "t.latency_ip, t.latency, t.latency_enable, t.loss_ip, t.loss_percentage, t.loss_enable "
        "FROM public.sdwan_tunnels t "
        "JOIN public.interfaces i ON t.local = i.id "
        "WHERE t.profile_id = $1 ORDER BY t.id",
        1, NULL, paramValues, NULL, NULL, 0);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT sdwan_tunnels JOIN interfaces failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    int num_tunnels = PQntuples(res);
    if (num_tunnels > MAX_SDWAN_TUNS) {
        log_error("Profile %d has %d tunnels, but this build supports at most %d",
                  profile_id, num_tunnels, MAX_SDWAN_TUNS);
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    cfg->sdwan_tun_count = (size_t)num_tunnels;
    
    for (size_t i = 0; i < cfg->sdwan_tun_count; i++) {
        if (parse_tunnel_row(res, (int)i, cfg->weight_enabled,
                             &cfg->sdwan_tuns[i]) < 0) {
            PQclear(res);
            pthread_mutex_unlock(&g_db_mutex);
            return -1;
        }
    }
    PQclear(res);
    
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

int db_client_load_tunnel(int profile_id, const char *tunnel_name,
                          bool weight_enabled, sdwan_tun_cfg_t *tun)
{
    char id_str[16];
    const char *params[2];
    PGresult *res;
    int ret = -1;

    if (!tunnel_name || !*tunnel_name || !tun)
        return -1;

    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    params[0] = id_str;
    params[1] = tunnel_name;
    res = PQexecParams(g_db_conn,
        "SELECT t.tunnel_name, i.interface, t.ip_addr, t.segment_id, t.weight, "
        "t.latency_ip, t.latency, t.latency_enable, t.loss_ip, t.loss_percentage, t.loss_enable "
        "FROM public.sdwan_tunnels t "
        "JOIN public.interfaces i ON t.local = i.id "
        "WHERE t.profile_id = $1 AND t.tunnel_name = $2",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT tunnel %s failed: %s", tunnel_name,
                  PQerrorMessage(g_db_conn));
    } else if (PQntuples(res) != 1) {
        log_error("Expected one tunnel named %s for profile %d, got %d",
                  tunnel_name, profile_id, PQntuples(res));
    } else {
        ret = parse_tunnel_row(res, 0, weight_enabled, tun);
    }

    PQclear(res);
    pthread_mutex_unlock(&g_db_mutex);
    return ret;
}

int db_client_load_pqc_identity(int profile_id, char *local_fg_out, char *peer_pub_out) {
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *paramValues[1] = { id_str };

    /* JOIN sdwan_pqc_ref with pqc_keys to get key_id, local, remote (no status field) */
    PGresult *res = PQexecParams(g_db_conn,
        "SELECT k.key_id, k.local, k.remote "
        "FROM public.sdwan_pqc_ref r "
        "JOIN public.pqc_keys k ON r.key_id = k.key_id "
        "WHERE r.profile_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT sdwan_pqc_ref JOIN pqc_keys failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -2; /* Not found */
    }

    strncpy(local_fg_out, PQgetvalue(res, 0, 1), 31);
    local_fg_out[31] = '\0';
    strncpy(peer_pub_out, PQgetvalue(res, 0, 2), 255);
    peer_pub_out[255] = '\0';

    PQclear(res);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

int db_client_load_pqc_exchange_tunnel(int profile_id, char *tunnel_name, size_t tn_len, char *tunnel_ip, size_t tip_len, char *peer_tunnel_ip, size_t ptip_len) {
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *paramValues[1] = { id_str };

    /* JOIN sdwan_tunnel_ref with pqc_exchange_tunnels for the 3 core fields */
    PGresult *res = PQexecParams(g_db_conn,
        "SELECT e.tunnel_name, e.tunnel_ip, e.peer_tunnel_ip "
        "FROM public.sdwan_tunnel_ref r "
        "JOIN public.pqc_exchange_tunnels e ON r.tunnel_id = e.tunnel_name "
        "WHERE r.profile_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT sdwan_tunnel_ref JOIN pqc_exchange_tunnels failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -2; /* Not found */
    }

    if (tunnel_name && tn_len > 0) {
        strncpy(tunnel_name, PQgetvalue(res, 0, 0), tn_len - 1);
        tunnel_name[tn_len - 1] = '\0';
    }
    if (tunnel_ip && tip_len > 0) {
        strncpy(tunnel_ip, PQgetvalue(res, 0, 1), tip_len - 1);
        tunnel_ip[tip_len - 1] = '\0';
    }
    if (peer_tunnel_ip && ptip_len > 0) {
        strncpy(peer_tunnel_ip, PQgetvalue(res, 0, 2), ptip_len - 1);
        peer_tunnel_ip[ptip_len - 1] = '\0';
    }

    PQclear(res);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}
