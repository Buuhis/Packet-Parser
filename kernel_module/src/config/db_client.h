#ifndef DB_CLIENT_H
#define DB_CLIENT_H

#include "app_context.h"
#include <libpq-fe.h>
#include <pthread.h>

extern PGconn *g_db_conn;
extern pthread_mutex_t g_db_mutex;

int db_client_connect(const char *host, const char *port, const char *user, const char *dbname, const char *password);
void db_client_disconnect(void);
int db_client_load_config(int node_id, app_config_t *cfg);

void db_client_start_heartbeat(int node_id);
void db_client_stop_heartbeat(void);
void db_client_report_error(int node_id, const char *err_msg);
int db_client_load_pqc_identity(int node_id, char *local_fg, char *peer_pub_name);

#endif /* DB_CLIENT_H */
