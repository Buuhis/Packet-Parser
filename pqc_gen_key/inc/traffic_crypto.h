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

typedef struct {
    SCryptCipherCtx* l2_ctx;
    SCryptCipherCtx* l3_ctx;
    SCryptCipherCtx* l4_ctx;
} TrfPqcContext;

int trf_pqc_init_global();
int trf_pqc_generate_random_key(byte* out, int len);
int trf_pqc_generate_nonce(byte* out_nonce);
const char* trf_pqc_error_string(int err);

void trf_pqc_cleanup();
void trf_base64_encode(const unsigned char *src, size_t len, char *out);
void trf_base64_encode_obfuscated(const unsigned char *src, size_t len, const char *seed, char *out);
void trf_base64_decode(const char *src, unsigned char *out, size_t *out_len);
void trf_base64_decode_obfuscated(const char *src, const char *seed, unsigned char *out, size_t *out_len);

int trf_encrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* new_len_out);

int trf_decrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* orig_len_out);

int trf_encrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len);
int trf_decrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len);

int trf_encrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* new_len_out);

int trf_decrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* orig_len_out);

int trf_calculate_digest(SCryptDigestType type, const byte* data, int len, byte* digest_out);

int trf_calculate_hmac(SCryptDigestType type, const byte* key, int key_len, 
                       const byte* data, int len, byte* mac_out);

int trf_kem_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz);

int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, 
                        byte* cipher_capsule_out, int* ctx_sz, 
                        byte* shared_secret_out);

int trf_kem_decapsulate(const byte* priv_key_in, int priv_sz, 
                        const byte* cipher_capsule_in, int ctx_sz, 
                        byte* shared_secret_out);

int trf_derive_session_keys(const byte* shared_secret, int ss_len, 
                            byte* tx_key_out, byte* rx_key_out);

int trf_dsa_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz);

int trf_dsa_sign_payload(const byte* priv_key_in, int priv_sz, 
                         const byte* data, int len, 
                         byte* sig_out, int* sig_sz);

int trf_dsa_verify_payload(const byte* pub_key_in, int pub_sz, 
                           const byte* data, int len, 
                           const byte* sig_in, int sig_sz);

typedef struct {
    byte tx_key[32];
    byte rx_key[32];
    int  is_active;
} trf_pqc_session;

int trf_pqc_setup_session(const byte* local_priv_dsa, int local_priv_dsa_sz,
                         const byte* remote_pub_dsa, int remote_pub_dsa_sz,
                         const byte* remote_pub_kem, int remote_pub_kem_sz,
                         trf_pqc_session* session_out);

#ifdef __cplusplus
}
#endif

#endif
