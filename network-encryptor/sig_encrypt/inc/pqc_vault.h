#ifndef PQC_VAULT_H
#define PQC_VAULT_H

#include <stddef.h>
#include <stdbool.h>

#define VAULT_PATH_LOCAL_PUBLIC  "local_public"
#define VAULT_PATH_LOCAL_PRIVATE "local_private"
#define VAULT_PATH_REMOTE_PUBLIC "remote_public"

/**
 * Initializes the Vault client by reading configuration from .env file or environment variables.
 * Variables read: LISTEN_PORT, UNSEAL_KEY1, UNSEAL_KEY2, UNSEAL_KEY3, VAULT_ADDR, VAULT_TOKEN.
 * @return 0 on success, -1 on failure.
 */
int sig_pqc_init_vault(void);

/**
 * Checks if Vault is sealed via GET /v1/sys/seal-status.
 * If sealed, automatically sends UNSEAL_KEY1, UNSEAL_KEY2, UNSEAL_KEY3 via POST /v1/sys/unseal.
 * @return 0 if Vault is unsealed (or unsealed successfully), -1 if Vault remains sealed.
 */
int sig_pqc_vault_ensure_unsealed(void);

/**
 * Reads a secret key (Base64 string) from HashiCorp Vault.
 * HTTP GET /v1/kv/data/PQC_Key/<path_type>/<fingerprint_filename>
 * @param path_type "local_public", "local_private", or "remote_public"
 * @param fingerprint_filename e.g. "qwerty.key" or "qwerty"
 * @param out_key_buf Output buffer to store the retrieved Base64 key string
 * @param max_len Size of out_key_buf
 * @return 0 on success, -1 on failure.
 */
int sig_pqc_vault_read_key(const char *path_type, const char *fingerprint_filename, char *out_key_buf, size_t max_len);

/**
 * Writes a secret key (Base64 string) to HashiCorp Vault.
 * HTTP POST /v1/kv/data/PQC_Key/<path_type>/<fingerprint_filename>
 * @param path_type "local_public", "local_private", or "remote_public"
 * @param fingerprint_filename e.g. "qwerty.key" or "qwerty"
 * @param key_content The Base64 key string to store
 * @return 0 on success, -1 on failure.
 */
int sig_pqc_vault_write_key(const char *path_type, const char *fingerprint_filename, const char *key_content);

#endif /* PQC_VAULT_H */
