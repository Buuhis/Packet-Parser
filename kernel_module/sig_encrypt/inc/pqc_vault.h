#ifndef PQC_VAULT_H
#define PQC_VAULT_H

#include <stddef.h>
#include <stdbool.h>

#define VAULT_PATH_LOCAL_PUBLIC  "local_public"
#define VAULT_PATH_LOCAL_PRIVATE "local_private"
#define VAULT_PATH_REMOTE_PUBLIC "remote_public"

int sig_pqc_init_vault(void);
int sig_pqc_vault_ensure_unsealed(void);
int sig_pqc_vault_read_key(const char *path_type, const char *fingerprint_filename, char *out_key_buf, size_t max_len);
int sig_pqc_vault_write_key(const char *path_type, const char *fingerprint_filename, const char *key_content);

#endif
