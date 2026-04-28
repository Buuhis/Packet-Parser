#ifndef __TRAFFIC_CRYPTO_H__
#define __TRAFFIC_CRYPTO_H__

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define TRF_PQC_OK 0
#define TRF_PQC_ERR_INIT -1
#define TRF_PQC_ERR_CRYPTO -2
#define TRF_PQC_ERR_SIG -3

#define PQC_BUFF_MAX 8192

// Library lifecycle
int trf_pqc_init();
void trf_pqc_cleanup();
int trf_pqc_generate_random_key(byte* out, int len);
int trf_pqc_generate_nonce(byte* out_nonce);

// =========================================================
// DATA PLANE: AES-256-GCM (AEAD)
// =========================================================

/**
 * @brief Encrypts payload using AES-GCM-256 with AAD support.
 * Format: [Nonce] + [Encrypted Data] + [Tag]
 */
int trf_encrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* new_len_out);

/**
 * @brief Decrypts payload and verifies integrity using AES-GCM-256.
 */
int trf_decrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* orig_len_out);

// =========================================================
// CONTROL PLANE: PQC KEY EXCHANGE (ML-KEM)
// =========================================================

int trf_kem_generate_keys(byte* pub_out, int* pub_sz, byte* priv_out, int* priv_sz);

int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, byte* cipher_capsule_out, 
                        int* ctx_sz, byte* shared_secret_out);

int trf_kem_decapsulate(const byte* priv_key_in, int priv_sz, 
                        const byte* cipher_capsule_in, int ctx_sz, 
                        byte* shared_secret_out);

// =========================================================
// CONTROL PLANE: PQC DIGITAL SIGNATURES (ML-DSA)
// =========================================================

int trf_dsa_generate_keys(byte* pub_out, int* pub_sz, byte* priv_out, int* priv_sz);

int trf_dsa_sign_payload(const byte* priv_key, int priv_sz, const byte* msg, 
                         int msg_sz, byte* sig_out, int* sig_sz);

int trf_dsa_verify_payload(const byte* pub_key, int pub_sz, const byte* msg, 
                           int msg_sz, const byte* sig, int sig_sz);

// =========================================================
// KEY DERIVATION
// =========================================================

int trf_derive_session_keys(const byte* shared_secret, int ss_len, 
                             byte* tx_key_out, byte* rx_key_out);

#ifdef __cplusplus
}
#endif

#endif // __TRAFFIC_CRYPTO_H__
