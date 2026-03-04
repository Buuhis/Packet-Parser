#ifndef DB_CLIENT_H
#define DB_CLIENT_H

#include "app_context.h"
#include <libpq-fe.h>

extern PGconn *g_db_conn;

int db_client_connect(const char *host, const char *port, const char *user, const char *dbname, const char *password);
void db_client_disconnect(void);
int db_client_load_config(const char *node_id, app_config_t *cfg);

#endif /* DB_CLIENT_H */
