#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypt.h"

// =========================================================
// PQC CONSTANTS & CONFIGURATION
// =========================================================

#define PQC_MLKEM_LEVEL     MLKEM_LEVEL_5
#define PQC_MLDSA_LEVEL     MLDSA_LEVEL_3

#define TAG_SIZE_GCM        16
#define NONCE_SIZE_GCM      12

static int g_pqc_initialized = 0;

// Helper function to handle memory alignment for Atom architecture
static void* get_aligned_library_obj(void* (*new_func)(), void (*free_func)(void*)) {
    void* ptrs[1024];
    int count = 0;
    void* target = NULL;

    for (count = 0; count < 1024; count++) {
        void* obj = new_func();
        if (!obj) break;
        if (((uintptr_t)obj % 64) == 0) {
            target = obj;
            break;
        }
        ptrs[count] = obj;
    }
    
    // Free all unaligned objects
    for (int i = 0; i < count; i++) {
        free_func(ptrs[i]);
    }

    if (!target) {
        fprintf(stderr, "[PQC-CRITICAL] Failed to align object after 1024 attempts\n");
    }
    return target;
}

int trf_pqc_init() {
    if (scrypt_Init() == 0) {
        g_pqc_initialized = 1;
        return TRF_PQC_OK;
    }
    return TRF_PQC_ERR_INIT;
}

void trf_pqc_cleanup() {
    scrypt_Cleanup();
    g_pqc_initialized = 0;
}

int trf_pqc_generate_random_key(byte* out, int len) {
    if (scrypt_RandomBytes(out, len) == 0) return TRF_PQC_OK;
    return TRF_PQC_ERR_CRYPTO;
}

int trf_pqc_generate_nonce(byte* out_nonce) {
    if (scrypt_RandomBytes(out_nonce, NONCE_SIZE_GCM) == 0) return TRF_PQC_OK;
    return TRF_PQC_ERR_CRYPTO;
}

// =========================================================
// DATA PLANE: AES-256-GCM (AEAD)
// =========================================================

/**
 * @brief Encrypts payload using AES-GCM-256 with AAD support.
 * Format: [Nonce] + [Encrypted Data] + [Tag]
 */
int trf_encrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* new_len_out) {
    if (!g_pqc_initialized || !data || len == 0) return TRF_PQC_ERR_CRYPTO;

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    int ret;
    if ((ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_ENCRYPTION)) != 0) {
        goto err;
    }

    scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);

    // Process Additional Authenticated Data (Headers)
    if (aad && aad_len > 0) {
        scrypt_CipherUpdateAAD(ctx, aad, aad_len);
    }

    word32 outLen = 0, finalLen = 0;
    if ((ret = scrypt_CipherUpdate(ctx, data, len, data, &outLen)) != 0) goto err;
    if ((ret = scrypt_CipherFinal(ctx, data + outLen, &finalLen)) != 0) goto err;

    byte tag[TAG_SIZE_GCM];
    word32 tagLen = TAG_SIZE_GCM;
    if ((ret = scrypt_CipherGetTag(ctx, tag, &tagLen)) != 0) goto err;

    // Append tag at the end of data
    memcpy(data + outLen + finalLen, tag, TAG_SIZE_GCM);
    *new_len_out = outLen + finalLen + TAG_SIZE_GCM;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

/**
 * @brief Decrypts payload and verifies integrity using AES-GCM-256.
 */
int trf_decrypt_payload_gcm(const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* orig_len_out) {
    if (!g_pqc_initialized || !data || len <= TAG_SIZE_GCM) return TRF_PQC_ERR_CRYPTO;

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) return TRF_PQC_ERR_CRYPTO;

    int ret;
    if ((ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_DECRYPTION)) != 0) {
        goto err;
    }

    int payload_len = len - TAG_SIZE_GCM;
    byte tag[TAG_SIZE_GCM];
    memcpy(tag, data + payload_len, TAG_SIZE_GCM);

    // Process AAD before or after Update depending on library requirement
    // Usually AAD must be processed first.
    if (aad && aad_len > 0) {
        scrypt_CipherUpdateAAD(ctx, aad, aad_len);
    }

    word32 outLen = 0, finalLen = 0;
    if ((ret = scrypt_CipherUpdate(ctx, data, payload_len, data, &outLen)) != 0) goto err;

    // Set expected tag for verification
    if ((ret = scrypt_CipherSetTag(ctx, tag, TAG_SIZE_GCM)) != 0) goto err;

    if ((ret = scrypt_CipherFinal(ctx, data + outLen, &finalLen)) != 0) {
        // Integrity check failed!
        goto err;
    }

    *orig_len_out = outLen + finalLen;

    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_OK;
err:
    scrypt_CipherCtxFree(ctx);
    return TRF_PQC_ERR_CRYPTO;
}

// =========================================================
// CONTROL PLANE: HANDSHAKE (ML-KEM & ML-DSA)
// =========================================================

int trf_kem_generate_keys(byte* pub_out, int* pub_sz, byte* priv_out, int* priv_sz) {
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlKemKeyNew, (void(*)(void*))scrypt_MlKemKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlKemKeyGen(key_obj, PQC_MLKEM_LEVEL) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *pub_sz = scrypt_MlKemExportPublicKey(key_obj, pub_out, PQC_BUFF_MAX);
    *priv_sz = scrypt_MlKemExportPrivateKey(key_obj, priv_out, PQC_BUFF_MAX);

    scrypt_MlKemKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, byte* cipher_capsule_out, 
                        int* ctx_sz, byte* shared_secret_out) {
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlKemKeyNew, (void(*)(void*))scrypt_MlKemKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlKemImportPublicKey(key_obj, pub_key_in, pub_sz, PQC_MLKEM_LEVEL) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *ctx_sz = scrypt_MlKemCipherTextSize(key_obj);
    int ss_sz = scrypt_MlKemSharedSecretSize(key_obj);

    if (scrypt_MlKemEncapsulate(key_obj, cipher_capsule_out, *ctx_sz, shared_secret_out, ss_sz) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    scrypt_MlKemKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_kem_decapsulate(const byte* priv_key_in, int priv_sz, 
                        const byte* cipher_capsule_in, int ctx_sz, 
                        byte* shared_secret_out) {
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlKemKeyNew, (void(*)(void*))scrypt_MlKemKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlKemImportPrivateKey(key_obj, priv_key_in, priv_sz, PQC_MLKEM_LEVEL) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    int ss_sz = scrypt_MlKemSharedSecretSize(key_obj);
    if (scrypt_MlKemDecapsulate(key_obj, shared_secret_out, ss_sz, cipher_capsule_in, ctx_sz) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    scrypt_MlKemKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_dsa_generate_keys(byte* pub_out, int* pub_sz, byte* priv_out, int* priv_sz) {
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlDsaKeyGen(key_obj, PQC_MLDSA_LEVEL) != 0) {
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *pub_sz = scrypt_MlDsaExportPublicKey(key_obj, pub_out, PQC_BUFF_MAX);
    *priv_sz = scrypt_MlDsaExportPrivateKey(key_obj, priv_out, PQC_BUFF_MAX);

    scrypt_MlDsaKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_dsa_sign_payload(const byte* priv_key, int priv_sz, const byte* msg, 
                         int msg_sz, byte* sig_out, int* sig_sz) {
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlDsaImportPrivateKey(key_obj, priv_key, priv_sz, PQC_MLDSA_LEVEL) != 0) {
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *sig_sz = scrypt_MlDsaSignatureSize(key_obj);
    if (scrypt_MlDsaSign(key_obj, msg, msg_sz, sig_out, *sig_sz) != 0) {
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    scrypt_MlDsaKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_dsa_verify_payload(const byte* pub_key, int pub_sz, const byte* msg, 
                           int msg_sz, const byte* sig, int sig_sz) {
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlDsaImportPublicKey(key_obj, pub_key, pub_sz, PQC_MLDSA_LEVEL) != 0) {
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    int ret = scrypt_MlDsaVerify(key_obj, msg, msg_sz, sig, sig_sz);
    scrypt_MlDsaKeyFree(key_obj);
    
    return (ret == 0) ? TRF_PQC_OK : TRF_PQC_ERR_CRYPTO;
}

int trf_derive_session_keys(const byte* shared_secret, int ss_len, 
                             byte* tx_key_out, byte* rx_key_out) {
    byte key_material[64] __attribute__((aligned(64)));
    
    const char* HKDF_SALT = "PQC_SECURE_SALT_V1";
    const char* HKDF_INFO = "PQC_SESSION_DERIVATION";

    if (scrypt_HKDF(DIGEST_TYPE_SHA512, shared_secret, ss_len, 
                    (const byte*)HKDF_SALT, strlen(HKDF_SALT), 
                    (const byte*)HKDF_INFO, strlen(HKDF_INFO), 
                    key_material, 64) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    memcpy(tx_key_out, key_material, 32);
    memcpy(rx_key_out, key_material + 32, 32);
    
    memset(key_material, 0, sizeof(key_material));
    return TRF_PQC_OK;
}
