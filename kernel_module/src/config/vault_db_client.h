#ifndef VAULT_DB_CLIENT_H
#define VAULT_DB_CLIENT_H

#include <stddef.h>

/**
 * Fetches PostgreSQL DB connection configuration directly from HashiCorp Vault.
 *
 * Vault Connection Parameters (VAULT_ADDR, VAULT_TOKEN) are read from .env or environment variables.
 * Queries Vault KV v2 REST API endpoint: /v1/kv/data/secret
 *
 * Populates:
 *  - server: POSTGRES_SERVER
 *  - port: POSTGRES_PORT
 *  - user: POSTGRES_USER
 *  - dbname: POSTGRES_DB
 *  - password: POSTGRES_PASSWORD
 *
 * Returns 0 on success, -1 on failure.
 */
int vault_db_fetch_config(char *server, size_t s_len,
                        char *port, size_t p_len,
                        char *user, size_t u_len,
                        char *dbname, size_t d_len,
                        char *password, size_t pass_len);

#endif /* VAULT_DB_CLIENT_H */
