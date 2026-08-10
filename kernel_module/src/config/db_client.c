#include "db_client.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

PGconn *g_db_conn = NULL;
pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t hb_thread;
static int hb_running = 0;
static int hb_node_id = 0;

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

int db_client_load_config(int node_id, app_config_t *cfg)
{
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        log_error("Database connection is not open.");
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    /* 1. Fetch node info (including encryption config) */
    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", node_id);
    const char *paramValues[1] = { id_str };
    
    PGresult *res = PQexecParams(g_db_conn,
        "SELECT local_if, "
        "encryption_enabled, encrypt_type, encrypt_key, encrypt_layer "
        "FROM public.nodes WHERE node_id = $1",
        1,       /* nParams */
        NULL,    /* paramTypes */
        paramValues,
        NULL,    /* paramLengths */
        NULL,    /* paramFormats */
        0);      /* resultFormat = text */
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT nodes failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    if (PQntuples(res) == 0) {
        log_error("No node found with id '%d'", node_id);
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    memset(cfg, 0, sizeof(*cfg));
    cfg->node_id = node_id;
    strncpy(cfg->local_if, PQgetvalue(res, 0, 0), sizeof(cfg->local_if) - 1);
    
    /* Parse encryption config */
    const char *enc_enabled = PQgetvalue(res, 0, 1);
    const char *enc_type    = PQgetvalue(res, 0, 2);
    const char *enc_key_hex = PQgetvalue(res, 0, 3);
    const char *enc_layer    = PQgetvalue(res, 0, 4);
    
    cfg->encrypt.enabled = (enc_enabled && strcmp(enc_enabled, "t") == 0);
    
    if (cfg->encrypt.enabled) {
        /* Set layer (default L3) */
        cfg->encrypt.layer = enc_layer ? atoi(enc_layer) : 3;

        /* Map string type to enum */
        if (enc_type && strcmp(enc_type, "aes-gcm-256") == 0) {
            cfg->encrypt.type = 1;  /* MWAN_CRYPT_AES_GCM_256 */
        } else if (enc_type && strcmp(enc_type, "pqc-gcm") == 0) {
            cfg->encrypt.type = 2;  /* MWAN_CRYPT_PQC_GCM */
        } else {
            cfg->encrypt.type = 0;  /* MWAN_CRYPT_AES_GCM_128 (default) */
        }
        
        /* Convert hex key to binary */
        if (enc_key_hex && strlen(enc_key_hex) > 0) {
            int klen = hex_to_bytes(enc_key_hex, cfg->encrypt.key, MAX_ENCRYPT_KEY_LEN);
            if (klen > 0) {
                cfg->encrypt.key_len = (size_t)klen;
            } else {
                log_error("Invalid encrypt_key hex string");
                cfg->encrypt.enabled = false;
            }
        }
    }
    PQclear(res);
    
    /* 2. Fetch sdwan_tuns info */
    res = PQexecParams(g_db_conn,
        "SELECT ifname, gateway, weight, port FROM public.sdwan_tuns WHERE node_id = $1 ORDER BY id",
        1, NULL, paramValues, NULL, NULL, 0);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT sdwan_tuns failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }
    
    int num_tunnels = PQntuples(res);
    cfg->sdwan_tun_count = (num_tunnels < MAX_SDWAN_TUNS) ? num_tunnels : MAX_SDWAN_TUNS;
    
    for (size_t i = 0; i < cfg->sdwan_tun_count; i++) {
        strncpy(cfg->sdwan_tuns[i].ifname, PQgetvalue(res, i, 0), sizeof(cfg->sdwan_tuns[i].ifname) - 1);
        strncpy(cfg->sdwan_tuns[i].gateway, PQgetvalue(res, i, 1), sizeof(cfg->sdwan_tuns[i].gateway) - 1);
        cfg->sdwan_tuns[i].weight = atoi(PQgetvalue(res, i, 2));
        cfg->sdwan_tuns[i].port = atoi(PQgetvalue(res, i, 3));
    }
    PQclear(res);
    
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}

static void *heartbeat_loop(void *arg) {
    (void)arg;
    while (hb_running) {
        pthread_mutex_lock(&g_db_mutex);
        if (g_db_conn && PQstatus(g_db_conn) == CONNECTION_OK) {
            char id_str[16];
            snprintf(id_str, sizeof(id_str), "%d", hb_node_id);
            const char *params[1] = {id_str};
            // Upsert node status
            const char *query = "INSERT INTO public.node_status (node_id, status, last_seen) "
                                "VALUES ($1, 'ONLINE', NOW()) "
                                "ON CONFLICT (node_id) DO UPDATE SET status = 'ONLINE', error_message = NULL, last_seen = NOW()";
            PGresult *res = PQexecParams(g_db_conn, query, 1, NULL, params, NULL, NULL, 0);
            if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                log_error("Heartbeat failed: %s", PQerrorMessage(g_db_conn));
            }
            PQclear(res);
        }
        pthread_mutex_unlock(&g_db_mutex);
        
        // Sleep in 1s chunks to allow quick exit
        for (int i=0; i<30 && hb_running; i++) {
            sleep(1);
        }
    }
    return NULL;
}

void db_client_start_heartbeat(int node_id) {
    hb_node_id = node_id;
    if (!hb_running) {
        hb_running = 1;
        pthread_create(&hb_thread, NULL, heartbeat_loop, NULL);
    }
}

void db_client_stop_heartbeat(void) {
    if (hb_running) {
        hb_running = 0;
        pthread_join(hb_thread, NULL);
    }
}

void db_client_report_error(int node_id, const char *err_msg) {
    pthread_mutex_lock(&g_db_mutex);
    if (g_db_conn && PQstatus(g_db_conn) == CONNECTION_OK) {
        char id_str[16];
        snprintf(id_str, sizeof(id_str), "%d", node_id);
        const char *params[2] = {id_str, err_msg};
        const char *query = "INSERT INTO public.node_status (node_id, status, error_message, last_seen) "
                            "VALUES ($1, 'ERROR', $2, NOW()) "
                            "ON CONFLICT (node_id) DO UPDATE SET status = 'ERROR', error_message = $2, last_seen = NOW()";
        PGresult *res = PQexecParams(g_db_conn, query, 2, NULL, params, NULL, NULL, 0);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_error("Failed to report error to DB: %s", PQerrorMessage(g_db_conn));
        }
        PQclear(res);
    }
    pthread_mutex_unlock(&g_db_mutex);
}

int db_client_load_pqc_identity(int node_id, char *local_fg_out, char *peer_pub_out) {
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", node_id);
    const char *paramValues[1] = { id_str };

    PGresult *res = PQexecParams(g_db_conn,
        "SELECT local_identity_fingerprint, peer_pub FROM public.pqc_identities WHERE node_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT pqc_identities failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -1;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        return -2; // Not found (might not be using PQC)
    }

    strncpy(local_fg_out, PQgetvalue(res, 0, 0), 31);
    local_fg_out[31] = '\0';
    strncpy(peer_pub_out, PQgetvalue(res, 0, 1), 255);
    peer_pub_out[255] = '\0';

    PQclear(res);
    pthread_mutex_unlock(&g_db_mutex);
    return 0;
}
