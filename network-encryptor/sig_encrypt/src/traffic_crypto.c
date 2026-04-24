#include "../inc/traffic_crypto.h"
#include "crypt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define TAG_SIZE_GCM 16
#define HKDF_SALT "network_encryptor_xdp_salt_v1"
#define HKDF_INFO "session_key_expansion"

// External declaration for the underlying symbol is no longer needed
static int g_pqc_initialized = 0;

int trf_pqc_generate_nonce(byte* out_nonce) {
    if (!out_nonce) return TRF_PQC_ERR_INIT;
    // Use the library's random generator as recommended by tutorial
    return scrypt_RandomBytes(out_nonce, 12);
}

const char* trf_pqc_error_string(int err) {
    return scrypt_ErrorString(err);
}

int trf_pqc_init_global() {
    if (g_pqc_initialized) return TRF_PQC_OK;
    
    int ret = scrypt_Init();
    if (ret != 0) {
        fprintf(stderr, "[PQC-INIT] scrypt_Init failed: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_INIT;
    }
    
    g_pqc_initialized = 1;
    return TRF_PQC_OK;
}

int trf_pqc_generate_random_key(byte* out, int len) {
    if (!out || len <= 0) return TRF_PQC_ERR_CRYPTO;
    int ret = scrypt_RandomBytes(out, (word32)len);
    if (ret != 0) {
        fprintf(stderr, "[PQC-RAND] Failed to generate random bytes: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_CRYPTO;
    }
    return TRF_PQC_OK;
}

void trf_pqc_cleanup() {
    if (!g_pqc_initialized) return;
    scrypt_Cleanup();
    g_pqc_initialized = 0;
}

// =========================================================
// DATA PLANE: ENCRYPTION
// =========================================================

// =========================================================
// DATA PLANE: ENCRYPTION (AES-GCM / AES-CBC)
// =========================================================

int trf_encrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            byte* data, int len, int* new_len_out) {
    if (!g_pqc_initialized || !data || len == 0) return TRF_PQC_ERR_CRYPTO;

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_ENCRYPTION) != 0) goto err;

    word32 outLen = 0, finalLen = 0;
    if (scrypt_CipherUpdate(ctx, data, len, data, &outLen) != 0) goto err;
    if (scrypt_CipherFinal(ctx, data + outLen, &finalLen) != 0) goto err;

    byte tag[TAG_SIZE_GCM];
    word32 tagLen = TAG_SIZE_GCM;
    if (scrypt_CipherGetTag(ctx, tag, &tagLen) != 0) goto err;

    memcpy(data + outLen + finalLen, tag, TAG_SIZE_GCM);
    *new_len_out = outLen + finalLen + TAG_SIZE_GCM;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

int trf_decrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            byte* data, int len, int* orig_len_out) {
    if (!g_pqc_initialized || !data || len <= TAG_SIZE_GCM) return TRF_PQC_ERR_CRYPTO;

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_DECRYPTION) != 0) goto err;

    int payload_len = len - TAG_SIZE_GCM;
    byte tag[TAG_SIZE_GCM];
    memcpy(tag, data + payload_len, TAG_SIZE_GCM);

    if (scrypt_CipherSetTag(ctx, tag, TAG_SIZE_GCM) != 0) goto err;

    word32 outLen = 0, finalLen = 0;
    if (scrypt_CipherUpdate(ctx, data, payload_len, data, &outLen) != 0) goto err;
    if (scrypt_CipherFinal(ctx, data + outLen, &finalLen) != 0) goto err;

    *orig_len_out = outLen + finalLen;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

int trf_encrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len) {
    if (!g_pqc_initialized || !data || len == 0) return TRF_PQC_ERR_CRYPTO;
    
    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_CBC, key, 32, iv, iv_len, SCRYPT_ENCRYPTION) != 0) goto err;

    word32 outLen = 0, finalLen = 0;
    if (scrypt_CipherUpdate(ctx, data, len, data, &outLen) != 0) goto err;
    if (scrypt_CipherFinal(ctx, data + outLen, &finalLen) != 0) goto err;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

int trf_decrypt_payload_cbc(const byte* key, const byte* iv, int iv_len, byte* data, int len) {
    if (!g_pqc_initialized || !data || len == 0) return TRF_PQC_ERR_CRYPTO;
    
    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_CBC, key, 32, iv, iv_len, SCRYPT_DECRYPTION) != 0) goto err;

    word32 outLen = 0, finalLen = 0;
    if (scrypt_CipherUpdate(ctx, data, len, data, &outLen) != 0) goto err;
    if (scrypt_CipherFinal(ctx, data + outLen, &finalLen) != 0) goto err;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

// =========================================================
// HASHING & MAC (SHA2 / SHA3 / HMAC)
// =========================================================

int trf_calculate_digest(SCryptDigestType type, const byte* data, int len, byte* digest_out) {
    SCryptDigestCtx* ctx = scrypt_DigestCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_DigestInit(ctx, type, 0) != 0) goto err;
    if (scrypt_DigestUpdate(ctx, data, len) != 0) goto err;
    if (scrypt_DigestFinal(ctx, digest_out) != 0) goto err;

    scrypt_DigestCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_DigestCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

int trf_calculate_hmac(SCryptDigestType type, const byte* key, int key_len, 
                       const byte* data, int len, byte* mac_out) {
    SCryptHmacCtx* ctx = scrypt_HmacCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    if (scrypt_HmacInit(ctx, key, key_len, type) != 0) goto err;
    if (scrypt_HmacUpdate(ctx, data, len) != 0) goto err;
    if (scrypt_HmacFinal(ctx, mac_out, 32) != 0) goto err;

    scrypt_HmacCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_HmacCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

// =========================================================
// COMPOSITE ENCRYPTION MODES (CBC + HMAC)
// =========================================================

#define HMAC_TAG_SIZE 32

int trf_encrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* new_len_out) {
    if (trf_encrypt_payload_cbc(enc_key, iv, iv_len, data, len) != TRF_PQC_OK)
        return TRF_PQC_ERR_CRYPTO;

    byte mac[HMAC_TAG_SIZE];
    if (trf_calculate_hmac(DIGEST_TYPE_SHA256, hmac_key, 32, data, len, mac) != TRF_PQC_OK)
        return TRF_PQC_ERR_CRYPTO;

    memcpy(data + len, mac, HMAC_TAG_SIZE);
    *new_len_out = len + HMAC_TAG_SIZE;

    return TRF_PQC_OK;
}

int trf_decrypt_cbc_hmac(const byte* enc_key, const byte* hmac_key,
                         const byte* iv, int iv_len,
                         byte* data, int len, int* orig_len_out) {
    if (len <= HMAC_TAG_SIZE) return TRF_PQC_ERR_CRYPTO;

    int cipher_len = len - HMAC_TAG_SIZE;
    byte received_mac[HMAC_TAG_SIZE];
    memcpy(received_mac, data + cipher_len, HMAC_TAG_SIZE);

    byte computed_mac[HMAC_TAG_SIZE];
    if (trf_calculate_hmac(DIGEST_TYPE_SHA256, hmac_key, 32, data, cipher_len, computed_mac) != TRF_PQC_OK)
        return TRF_PQC_ERR_CRYPTO;

    if (memcmp(received_mac, computed_mac, HMAC_TAG_SIZE) != 0)
        return TRF_PQC_ERR_CRYPTO;

    if (trf_decrypt_payload_cbc(enc_key, iv, iv_len, data, cipher_len) != TRF_PQC_OK)
        return TRF_PQC_ERR_CRYPTO;

    *orig_len_out = cipher_len;
    return TRF_PQC_OK;
}


// =========================================================
// CONTROL PLANE: PQC KEY EXCHANGE (ML-KEM LEVEL 5)
// =========================================================

// =========================================================
// CONTROL PLANE: PQC KEY EXCHANGE (ML-KEM LEVEL 5)
// =========================================================

int trf_kem_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz) {
    // Use aligned stack memory (Proven stable by USER)
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    if (scrypt_MlKemKeyGen(key_obj, MLKEM_LEVEL_5) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    *pub_sz = scrypt_MlKemPublicKeySize(key_obj);
    *priv_sz = scrypt_MlKemPrivateKeySize(key_obj);

    scrypt_MlKemExportPublicKey(key_obj, pub_key_out, *pub_sz);
    scrypt_MlKemExportPrivateKey(key_obj, priv_key_out, *priv_sz);

    return TRF_PQC_OK;
}

int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, 
                        byte* cipher_capsule_out, int* ctx_sz, 
                        byte* shared_secret_out) {
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    if (scrypt_MlKemImportPublicKey(key_obj, pub_key_in, pub_sz, MLKEM_LEVEL_5) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    *ctx_sz = scrypt_MlKemCipherTextSize(key_obj);
    int ss_sz = scrypt_MlKemShareSecretSize(key_obj);

    if (scrypt_MlKemEncapsulate(key_obj, cipher_capsule_out, *ctx_sz, shared_secret_out, ss_sz) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    return TRF_PQC_OK;
}

int trf_kem_decapsulate(const byte* priv_key_in, int priv_sz, 
                        const byte* cipher_capsule_in, int ctx_sz, 
                        byte* shared_secret_out) {
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    if (scrypt_MlKemImportPrivateKey(key_obj, priv_key_in, priv_sz, MLKEM_LEVEL_5) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    int ss_sz = scrypt_MlKemShareSecretSize(key_obj);

    if (scrypt_MlKemDecapsulate(key_obj, shared_secret_out, ss_sz, cipher_capsule_in, ctx_sz) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    return TRF_PQC_OK;
}

int trf_derive_session_keys(const byte* shared_secret, int ss_len, 
                            byte* tx_key_out, byte* rx_key_out) {
    byte key_material[64] __attribute__((aligned(64)));
    
    int ret = scrypt_HKDF(DIGEST_TYPE_SHA512, shared_secret, ss_len, 
                          (const byte*)HKDF_SALT, strlen(HKDF_SALT), 
                          (const byte*)HKDF_INFO, strlen(HKDF_INFO), 
                          key_material, 64);
                          
    if (ret != 0) return TRF_PQC_ERR_CRYPTO;

    memcpy(tx_key_out, key_material, 32);
    memcpy(rx_key_out, key_material + 32, 32);
    
    memset(key_material, 0, sizeof(key_material));
    return TRF_PQC_OK;
}


// =========================================================
// CONTROL PLANE: PQC DIGITAL SIGNATURES (ML-DSA LEVEL 5)
// =========================================================

int trf_dsa_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz) {
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    if (scrypt_MlDsaKeyGen(key_obj, MLDSA_LEVEL_5) != 0) {
        return TRF_PQC_ERR_SIG;
    }

    *pub_sz = scrypt_MlDsaPublicKeySize(key_obj);
    *priv_sz = scrypt_MlDsaPrivateKeySize(key_obj);

    scrypt_MlDsaExportPublicKey(key_obj, pub_key_out, *pub_sz);
    scrypt_MlDsaExportPrivateKey(key_obj, priv_key_out, *priv_sz);

    return TRF_PQC_OK;
}

int trf_dsa_sign_payload(const byte* priv_key_in, int priv_sz, 
                         const byte* data, int len, 
                         byte* sig_out, int* sig_sz) {
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    int ret_import = scrypt_MlDsaImportPrivateKey(key_obj, priv_key_in, priv_sz, MLDSA_LEVEL_5);
    if (ret_import != 0) {
        fprintf(stderr, "[DEBUG] DSA Import Private Key failed with code: %d\n", ret_import);
        return TRF_PQC_ERR_SIG;
    }

    int max_sig_sz = scrypt_MlDsaSignatureSize(key_obj);
    int ret = scrypt_MlDsaSign(key_obj, data, len, sig_out, max_sig_sz);
    
    if (ret < 0) {
        return TRF_PQC_ERR_SIG;
    }

    *sig_sz = ret;
    return TRF_PQC_OK;
}

int trf_dsa_verify_payload(const byte* pub_key_in, int pub_sz, 
                           const byte* data, int len, 
                           const byte* sig_in, int sig_sz) {
    byte key_mem[16384] __attribute__((aligned(64)));
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)key_mem;
    memset(key_mem, 0, sizeof(key_mem));

    if (scrypt_MlDsaImportPublicKey(key_obj, pub_key_in, pub_sz, MLDSA_LEVEL_5) != 0) {
        return TRF_PQC_ERR_SIG;
    }

    int ret = scrypt_MlDsaVerify(key_obj, data, len, sig_in, sig_sz);
    return (ret == 0) ? TRF_PQC_OK : TRF_PQC_ERR_SIG;
}
// =========================================================
// COMPOSITE PQC LOGIC (HANDSHAKE + DERIVATION)
// =========================================================

int trf_pqc_setup_session(const byte* local_priv_dsa, int local_priv_dsa_sz,
                         const byte* remote_pub_dsa, int remote_pub_dsa_sz,
                         const byte* remote_pub_kem, int remote_pub_kem_sz,
                         trf_pqc_session* session_out) {
    
    if (!g_pqc_initialized || !session_out) return TRF_PQC_ERR_INIT;

    byte shared_secret[64];
    byte capsule[2048]; 
    int capsule_sz = 0;
    int ss_sz = 64;
    int ret;

    // 1. ML-KEM: Encapsulate to get shared secret and capsule
    ret = trf_kem_encapsulate(remote_pub_kem, remote_pub_kem_sz, capsule, &capsule_sz, shared_secret);
    if (ret != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-KEM] Encapsulation failed: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_CRYPTO;
    }

    // 2. ML-DSA: Sign the capsule to ensure authenticity
    byte signature[5000]; 
    int sig_sz = 0;
    ret = trf_dsa_sign_payload(local_priv_dsa, local_priv_dsa_sz, capsule, capsule_sz, signature, &sig_sz);
    if (ret != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-DSA] Signing failed: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_SIG;
    }

    // 3. Verification: Simulate remote verification
    ret = trf_dsa_verify_payload(remote_pub_dsa, remote_pub_dsa_sz, capsule, capsule_sz, signature, sig_sz);
    if (ret != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-DSA] Signature verification failed: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_SIG;
    }

    // 4. HKDF: Expand shared secret into Session Keys
    ret = trf_derive_session_keys(shared_secret, ss_sz, session_out->tx_key, session_out->rx_key);
    if (ret != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HKDF] Key derivation failed: %s\n", scrypt_ErrorString(ret));
        return TRF_PQC_ERR_CRYPTO;
    }

    session_out->is_active = 1;
    memset(shared_secret, 0, sizeof(shared_secret));
    
    return TRF_PQC_OK;
}
