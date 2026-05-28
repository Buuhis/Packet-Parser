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

// Initialize the library once in main.c
int trf_pqc_init_global();
int trf_pqc_generate_random_key(byte* out, int len);
int trf_pqc_generate_nonce(byte* out_nonce);
const char* trf_pqc_error_string(int err);

// Cleanup resources before shutdown
void trf_pqc_cleanup();
void trf_base64_encode(const unsigned char *src, size_t len, char *out);
void trf_base64_encode_obfuscated(const unsigned char *src, size_t len, const char *seed, char *out);
void trf_base64_decode(const char *src, unsigned char *out, size_t *out_len);
void trf_base64_decode_obfuscated(const char *src, const char *seed, unsigned char *out, size_t *out_len);
int trf_save_key_to_file(const char *filename, const char *data, int mode);

// ===========================================
// DATA PLANE: AEAD IN-PLACE ENCRYPTION (GCM MODE)
// ===========================================

// Encrypt payload in-place. The 'data' buffer will be overwritten.
// Requirement (Tailroom): The allocated data_len must have at least (len + 16 bytes) capacity.
// A 16-byte authentication tag will be appended to the end of the 'data' array.
// aad: Optional Additional Authenticated Data (e.g. network headers)
int trf_encrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* new_len_out);

// Decrypt payload in-place. The 'data' buffer will be overwritten with plaintext.
// The function automatically extracts the 16-byte Tag at the end for authentication comparison.
// aad: Must match the AAD provided during encryption for successful authentication.
int trf_decrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* orig_len_out);

// ===========================================
// DATA PLANE: CBC + HMAC (Encrypt-then-MAC)
// ===========================================

// Low-level CBC encrypt/decrypt (used internally by CBC+HMAC combo)
int trf_encrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len);
int trf_decrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len);

// Combined CBC+HMAC Encrypt-then-MAC:
// 1. Encrypt data in-place with AES-256-CBC
// 2. Calculate HMAC-SHA256 over the ciphertext
// 3. Append 32-byte MAC tag to the end
// Requirement (Tailroom): buffer must have capacity for (len + 32 bytes).
int trf_encrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* new_len_out);

// Combined CBC+HMAC Decrypt (MAC-then-Decrypt):
// 1. Extract and verify 32-byte HMAC tag from the end
// 2. If MAC valid, decrypt with AES-256-CBC
// 3. If MAC invalid, return error immediately (prevent padding oracle)
int trf_decrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* orig_len_out);

// ===========================================
// HASHING & AUTHENTICATION (SHA2 / SHA3 / HMAC)
// ===========================================

// Calculate Hash/Digest (e.g., DIGEST_TYPE_SHA512, DIGEST_TYPE_SHA3_512)
int trf_calculate_digest(SCryptDigestType type, const byte* data, int len, byte* digest_out);

// Calculate HMAC for Message Authentication
int trf_calculate_hmac(SCryptDigestType type, const byte* key, int key_len, 
                       const byte* data, int len, byte* mac_out);


// ===========================================
// CONTROL PLANE: PQC KEY EXCHANGE (ML-KEM)
// ===========================================

// Generate ML-KEM keys (Level 5)
int trf_kem_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz);

// Client side: Use Server's Public Key to encapsulate and generate Shared Secret and Cipher Capsule.
int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, 
                        byte* cipher_capsule_out, int* ctx_sz, 
                        byte* shared_secret_out);

// Server side: Use Private Key to decapsulate the Capsule and retrieve the Shared Secret.
int trf_kem_decapsulate(const byte* priv_key_in, int priv_sz, 
                        const byte* cipher_capsule_in, int ctx_sz, 
                        byte* shared_secret_out);

// Use HKDF to expand the Shared Secret into standard Session Keys (enables Perfect Forward Secrecy)
int trf_derive_session_keys(const byte* shared_secret, int ss_len, 
                            byte* tx_key_out, byte* rx_key_out);


// ===========================================
// CONTROL PLANE: PQC DIGITAL SIGNATURES (ML-DSA)
// ===========================================

// Generate ML-DSA Keys (Level 5)
int trf_dsa_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz);

// Sign a payload/message (e.g. config update)
int trf_dsa_sign_payload(const byte* priv_key_in, int priv_sz, 
                         const byte* data, int len, 
                         byte* sig_out, int* sig_sz);

// Verify a payload signature
int trf_dsa_verify_payload(const byte* pub_key_in, int pub_sz, 
                           const byte* data, int len, 
                           const byte* sig_in, int sig_sz);


// =========================================================
// COMPOSITE PQC API (HANDSHAKE + DATA PLANE)
// =========================================================

typedef struct {
    byte tx_key[32];
    byte rx_key[32];
    int  is_active;
} trf_pqc_session;

/**
 * Perform a full PQC handshake exchange.
 * 1. Encapsulate/Decapsulate shared secret via ML-KEM
 * 2. Authenticate the exchange via ML-DSA signatures
 * 3. Expand session keys via HKDF (SHA-512)
 * 
 * This is a high-level wrapper used to maintain sig_encrypt isolation.
 */
int trf_pqc_setup_session(const byte* local_priv_dsa, int local_priv_dsa_sz,
                         const byte* remote_pub_dsa, int remote_pub_dsa_sz,
                         const byte* remote_pub_kem, int remote_pub_kem_sz,
                         trf_pqc_session* session_out);

#ifdef __cplusplus
}
#endif

#endif // __TRAFFIC_CRYPTO_H__
