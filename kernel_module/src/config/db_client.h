#ifndef DB_CLIENT_H
#define DB_CLIENT_H

#include "app_context.h"
#include <libpq-fe.h>
#include <pthread.h>

extern PGconn *g_db_conn;
extern pthread_mutex_t g_db_mutex;

int db_client_connect(const char *host, const char *port, const char *user, const char *dbname, const char *password);
void db_client_disconnect(void);
int db_client_load_config(int profile_id, app_config_t *cfg);
int db_client_load_tunnel(int profile_id, const char *tunnel_name,
                          bool weight_enabled, sdwan_tun_cfg_t *tun);

int db_client_load_pqc_identity(int profile_id, char *local_fg, char *peer_pub_name);
int db_client_load_pqc_exchange_tunnel(int profile_id, char *tunnel_name, size_t tn_len, char *tunnel_ip, size_t tip_len, char *peer_tunnel_ip, size_t ptip_len);

#endif /* DB_CLIENT_H */
