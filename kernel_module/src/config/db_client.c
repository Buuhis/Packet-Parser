#include "db_client.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

PGconn *g_db_conn = NULL;

static int parse_mac(const char *mac_str, unsigned char mac_bytes[6])
{
    int result = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
    return (result == 6) ? 0 : -1;
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
    if (!g_db_conn) {
        log_error("Database connection is not open.");
        return -1;
    }
    
    /* 1. Fetch node info */
    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", node_id);
    const char *paramValues[1] = { id_str };
    
    PGresult *res = PQexecParams(g_db_conn,
        "SELECT local_if, remote_cidr, loopback_ip FROM public.nodes WHERE node_id = $1",
        1,       /* nParams */
        NULL,    /* paramTypes */
        paramValues,
        NULL,    /* paramLengths */
        NULL,    /* paramFormats */
        0);      /* resultFormat = text */
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT nodes failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        return -1;
    }
    
    if (PQntuples(res) == 0) {
        log_error("No node found with id '%d'", node_id);
        PQclear(res);
        return -1;
    }
    
    memset(cfg, 0, sizeof(*cfg));
    cfg->node_id = node_id;
    strncpy(cfg->local_if, PQgetvalue(res, 0, 0), sizeof(cfg->local_if) - 1);
    strncpy(cfg->remote_cidr, PQgetvalue(res, 0, 1), sizeof(cfg->remote_cidr) - 1);
    strncpy(cfg->loopback_ip, PQgetvalue(res, 0, 2), sizeof(cfg->loopback_ip) - 1);
    PQclear(res);
    
    /* 2. Fetch ne_tunnels info */
    res = PQexecParams(g_db_conn,
        "SELECT ifname, gateway, weight, port FROM public.ne_tunnels WHERE node_id = $1 ORDER BY id",
        1, NULL, paramValues, NULL, NULL, 0);
        
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_error("SELECT ne_tunnels failed: %s", PQerrorMessage(g_db_conn));
        PQclear(res);
        return -1;
    }
    
    int num_tunnels = PQntuples(res);
    cfg->ne_tunnel_count = (num_tunnels < MAX_NE_TUNNELS) ? num_tunnels : MAX_NE_TUNNELS;
    
    for (size_t i = 0; i < cfg->ne_tunnel_count; i++) {
        strncpy(cfg->ne_tunnels[i].ifname, PQgetvalue(res, i, 0), sizeof(cfg->ne_tunnels[i].ifname) - 1);
        strncpy(cfg->ne_tunnels[i].gateway, PQgetvalue(res, i, 1), sizeof(cfg->ne_tunnels[i].gateway) - 1);
        cfg->ne_tunnels[i].weight = atoi(PQgetvalue(res, i, 2));
        cfg->ne_tunnels[i].port = atoi(PQgetvalue(res, i, 3));
    }
    PQclear(res);
    
    return 0;
}
