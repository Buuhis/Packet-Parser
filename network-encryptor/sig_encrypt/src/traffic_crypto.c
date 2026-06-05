#include "../inc/traffic_crypto.h"
#include "../inc/scrypt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define TAG_SIZE_GCM 16
#define HKDF_SALT "network_encryptor_xdp_salt_v1"
#define HKDF_INFO "session_key_expansion"

// External declaration for the underlying symbol is no longer needed
static int g_pqc_initialized = 0;

static __thread uint8_t tls_pqc_salt[8];
static __thread uint32_t tls_pqc_counter = 0;
static __thread int tls_salt_initialized = 0;

static void* get_aligned_library_obj(void* (*new_func)(), void (*free_func)(void*));

int trf_pqc_generate_nonce(byte* out_nonce) {
    if (!out_nonce) return TRF_PQC_ERR_INIT;
    
    // Generate random 8-byte salt ONCE per thread/session
    if (__builtin_expect(!tls_salt_initialized, 0)) {
        int ret = scrypt_RandomBytes(tls_pqc_salt, 8);
        if (__builtin_expect(ret != 0, 0)) {
            return TRF_PQC_ERR_CRYPTO;
        }
        tls_salt_initialized = 1;
    }
    
    // Increment local packet counter
    uint32_t cnt = ++tls_pqc_counter;
    
    // Nonce (12 bytes) = 8-byte Salt + 4-byte Counter
    memcpy(out_nonce, tls_pqc_salt, 8);
    memcpy(out_nonce + 8, &cnt, 4);
    
    return 0; // Success
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

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void trf_base64_encode(const unsigned char *src, size_t len, char *out) {
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1 < len) v |= (uint32_t)src[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)src[i + 2];
        out[j] = base64_chars[(v >> 18) & 0x3F];
        out[j + 1] = base64_chars[(v >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? base64_chars[(v >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? base64_chars[v & 0x3F] : '=';
    }
    out[j] = '\0';
}

void trf_base64_encode_obfuscated(const unsigned char *src, size_t len, const char *seed, char *out) {
    unsigned char *tmp = malloc(len);
    size_t seed_len = strlen(seed);
    for (size_t i = 0; i < len; i++) {
        tmp[i] = src[i] ^ seed[i % seed_len];
    }
    trf_base64_encode(tmp, len, out);
    free(tmp);
}

void trf_base64_decode(const char *src, unsigned char *out, size_t *out_len) {
    static const int b64_inv[256] = { [0 ... 255] = -1,
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };

    size_t in_len = strlen(src);
    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        if (src[i] == '\0') break;
        uint32_t v = (b64_inv[(int)src[i]] << 18) | (b64_inv[(int)src[i+1]] << 12);
        out[j++] = (v >> 16) & 0xFF;
        if (src[i+2] != '=') {
            v |= (b64_inv[(int)src[i+2]] << 6);
            out[j++] = (v >> 8) & 0xFF;
        }
        if (src[i+3] != '=') {
            v |= b64_inv[(int)src[i+3]];
            out[j++] = v & 0xFF;
        }
    }
    *out_len = j;
}

void trf_base64_decode_obfuscated(const char *src, const char *seed, unsigned char *out, size_t *out_len) {
    // This is a simplified decode + de-XOR. 
    // In a real system we'd need a proper Base64 decoder.
    // For now, let's assume the caller provides the decoded buffer or use a placeholder.
    // I will implement a basic decoder to ensure it's functional.
    static const int b64_inv[256] = { [0 ... 255] = -1,
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };

    size_t in_len = strlen(src);
    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        uint32_t v = (b64_inv[(int)src[i]] << 18) | (b64_inv[(int)src[i+1]] << 12);
        out[j++] = (v >> 16) & 0xFF;
        if (src[i+2] != '=') {
            v |= (b64_inv[(int)src[i+2]] << 6);
            out[j++] = (v >> 8) & 0xFF;
        }
        if (src[i+3] != '=') {
            v |= b64_inv[(int)src[i+3]];
            out[j++] = v & 0xFF;
        }
    }
    *out_len = j;

    // De-XOR
    size_t seed_len = strlen(seed);
    for (size_t i = 0; i < j; i++) {
        out[i] ^= seed[i % seed_len];
    }
}

int trf_save_key_to_file(const char *filename, const char *data, int mode) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, strlen(data));
    write(fd, "\n", 1);
    close(fd);
    return (written > 0) ? 0 : -1;
}

// =========================================================
// DATA PLANE: ENCRYPTION
// =========================================================

// =========================================================
// DATA PLANE: ENCRYPTION (AES-GCM / AES-CBC)
// =========================================================

int trf_encrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* new_len_out) {
    if (!g_pqc_initialized || !data || len == 0 || !ctx) return TRF_PQC_ERR_CRYPTO;

    int ret;
    if ((ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_ENCRYPTION)) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    // Explicitly set tag size for GCM
    scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);

    // Optional AAD - Must be 64-byte aligned for hardware acceleration to process it
    if (aad && aad_len > 0) {
        byte aligned_aad[256] __attribute__((aligned(64)));
        if (aad_len > (int)sizeof(aligned_aad)) return TRF_PQC_ERR_CRYPTO;
        memcpy(aligned_aad, aad, aad_len);
        if ((ret = scrypt_CipherUpdateAAD(ctx, aligned_aad, (word32)aad_len)) != 0) {
            return TRF_PQC_ERR_CRYPTO;
        }
    }

    word32 outLen = 0, finalLen = 0;
    if ((ret = scrypt_CipherUpdate(ctx, data, len, data, &outLen)) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }
    
    // GCM Final usually handles authentication tag generation
    if ((ret = scrypt_CipherFinal(ctx, data + outLen, &finalLen)) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    byte tag[TAG_SIZE_GCM];
    word32 tagLen = TAG_SIZE_GCM;
    if ((ret = scrypt_CipherGetTag(ctx, tag, &tagLen)) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    memcpy(data + outLen + finalLen, tag, TAG_SIZE_GCM);
    *new_len_out = outLen + finalLen + TAG_SIZE_GCM;

    return TRF_PQC_OK;
}

int trf_decrypt_payload_gcm(SCryptCipherCtx* ctx, const byte* key, const byte* nonce, int nonce_len, 
                            const byte* aad, int aad_len,
                            byte* data, int len, int* orig_len_out) {
    if (!g_pqc_initialized || !data || len <= TAG_SIZE_GCM || !ctx) return TRF_PQC_ERR_CRYPTO;

    int ret;
    if ((ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, nonce_len, SCRYPT_DECRYPTION)) != 0) {
        return TRF_PQC_ERR_CRYPTO;
    }

    // CRITICAL FIX: Explicitly set the expected tag size for the context
    scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);

    int payload_len = len - TAG_SIZE_GCM;
    byte tag[TAG_SIZE_GCM];
    memcpy(tag, data + payload_len, TAG_SIZE_GCM);

    // 1. Set tag for verification first
    if (scrypt_CipherSetTag(ctx, tag, TAG_SIZE_GCM) != 0) return TRF_PQC_ERR_CRYPTO;

    // 1. Process AAD (Network Header) - Align to 64-byte for hardware acceleration
    if (aad && aad_len > 0) {
        byte aligned_aad[256] __attribute__((aligned(64)));
        if (aad_len > (int)sizeof(aligned_aad)) return TRF_PQC_ERR_CRYPTO;
        memcpy(aligned_aad, aad, aad_len);
        if (scrypt_CipherUpdateAAD(ctx, aligned_aad, (word32)aad_len) != 0) return TRF_PQC_ERR_CRYPTO;
    }

    // 3. Process Ciphertext
    word32 outLen = 0, finalLen = 0;
    if (scrypt_CipherUpdate(ctx, data, payload_len, data, &outLen) != 0) return TRF_PQC_ERR_CRYPTO;
    
    // 4. Finalize and verify integrity (returns non-zero if AAD or Data was tampered)
    if (scrypt_CipherFinal(ctx, data + outLen, &finalLen) != 0) return TRF_PQC_ERR_CRYPTO;

    *orig_len_out = outLen + finalLen;
    return TRF_PQC_OK;
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
    SCryptDigestCtx* ctx = (SCryptDigestCtx*)get_aligned_library_obj(
        (void*(*)())scrypt_DigestCtxNew, (void(*)(void*))scrypt_DigestCtxFree);
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


// Helper to get an ALIGNED object from the library's own constructor
// This is necessary because the library's New() might return unaligned memory
// which crashes the CPU, but manual buffers (memset 0) cause BAD_FUNC_ARG (-173).
static void* get_aligned_library_obj(void* (*new_func)(), void (*free_func)(void*)) {
    void* pool[1024]; // Large pool for retries
    int count = 0;
    void* aligned_ptr = NULL;

    for (int i = 0; i < 1024; i++) {
        void* ptr = new_func();
        if (!ptr) break;

        if (((uintptr_t)ptr % 64) == 0) {
            aligned_ptr = ptr;
            break;
        }
        pool[count++] = ptr;
    }

    // Free the unaligned ones
    for (int i = 0; i < count; i++) {
        free_func(pool[i]);
    }

    if (!aligned_ptr) {
        fprintf(stderr, "[PQC] Critical: Failed to get aligned object after 1024 attempts\n");
    }
    return aligned_ptr;
}

int trf_kem_generate_keys(byte* pub_key_out, int* pub_sz, byte* priv_key_out, int* priv_sz) {
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlKemKeyNew, (void(*)(void*))scrypt_MlKemKeyFree);
    
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlKemKeyGen(key_obj, MLKEM_LEVEL_5) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *pub_sz = scrypt_MlKemPublicKeySize(key_obj);
    *priv_sz = scrypt_MlKemPrivateKeySize(key_obj);

    scrypt_MlKemExportPublicKey(key_obj, pub_key_out, *pub_sz);
    scrypt_MlKemExportPrivateKey(key_obj, priv_key_out, *priv_sz);

    scrypt_MlKemKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_kem_encapsulate(const byte* pub_key_in, int pub_sz, 
                        byte* cipher_capsule_out, int* ctx_sz, 
                        byte* shared_secret_out) {
    SCryptMlKemKey* key_obj = (SCryptMlKemKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlKemKeyNew, (void(*)(void*))scrypt_MlKemKeyFree);
    
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlKemImportPublicKey(key_obj, pub_key_in, pub_sz, MLKEM_LEVEL_5) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    *ctx_sz = scrypt_MlKemCipherTextSize(key_obj);
    int ss_sz = scrypt_MlKemShareSecretSize(key_obj);

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

    if (scrypt_MlKemImportPrivateKey(key_obj, priv_key_in, priv_sz, MLKEM_LEVEL_5) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    int ss_sz = scrypt_MlKemShareSecretSize(key_obj);

    if (scrypt_MlKemDecapsulate(key_obj, shared_secret_out, ss_sz, cipher_capsule_in, ctx_sz) != 0) {
        scrypt_MlKemKeyFree(key_obj);
        return TRF_PQC_ERR_CRYPTO;
    }

    scrypt_MlKemKeyFree(key_obj);
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
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    
    if (!key_obj) return TRF_PQC_ERR_INIT;

    if (scrypt_MlDsaKeyGen(key_obj, MLDSA_LEVEL_5) != 0) {
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_SIG;
    }

    *pub_sz = scrypt_MlDsaPublicKeySize(key_obj);
    *priv_sz = scrypt_MlDsaPrivateKeySize(key_obj);

    int written_pub = scrypt_MlDsaExportPublicKey(key_obj, pub_key_out, *pub_sz);
    int written_priv = scrypt_MlDsaExportPrivateKey(key_obj, priv_key_out, *priv_sz);

    printf("[DEBUG-DSA] Export Done: Pub=%d/%d, Priv=%d/%d\n", 
            written_pub, *pub_sz, written_priv, *priv_sz);

    // CRITICAL FIX: The library gave us 7488 for size but only wrote 4896.
    // We MUST use the actual written size for subsequent imports.
    *priv_sz = written_priv;
    *pub_sz = written_pub;

    scrypt_MlDsaKeyFree(key_obj);
    
    if (written_pub > 0 && written_priv > 0) {
        return TRF_PQC_OK;
    }
    return TRF_PQC_ERR_SIG;
}

int trf_dsa_sign_payload(const byte* priv_key_in, int priv_sz, 
                         const byte* data, int len, 
                         byte* sig_out, int* sig_sz) {
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    
    if (!key_obj) return TRF_PQC_ERR_INIT;

    // Clean Import into a new object
    int ret_import = scrypt_MlDsaImportPrivateKey(key_obj, priv_key_in, priv_sz, MLDSA_LEVEL_5);
    
    if (ret_import != 0) {
        fprintf(stderr, "[FAIL] DSA Import Private Key failed with code: %d (Size: %d, Level: %d)\n", 
                ret_import, priv_sz, MLDSA_LEVEL_5);
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_SIG;
    }

    int max_sig_sz = scrypt_MlDsaSignatureSize(key_obj);
    int ret = scrypt_MlDsaSign(key_obj, data, len, sig_out, max_sig_sz);
    
    if (ret < 0) {
        fprintf(stderr, "[FAIL] DSA Signing failed with code: %d\n", ret);
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_SIG;
    }

    *sig_sz = ret;
    scrypt_MlDsaKeyFree(key_obj);
    return TRF_PQC_OK;
}

int trf_dsa_verify_payload(const byte* pub_key_in, int pub_sz, 
                           const byte* data, int len, 
                           const byte* sig_in, int sig_sz) {
    SCryptMlDsaKey* key_obj = (SCryptMlDsaKey*)get_aligned_library_obj(
        (void*(*)())scrypt_MlDsaKeyNew, (void(*)(void*))scrypt_MlDsaKeyFree);
    
    if (!key_obj) return TRF_PQC_ERR_INIT;

    fprintf(stderr, "[DEBUG-VERIFY] Entering trf_dsa_verify_payload...\n");
    fprintf(stderr, "[DEBUG-VERIFY] pub_sz = %d, len = %d, sig_sz = %d\n", pub_sz, len, sig_sz);

    // Calculate fingerprint of incoming public key to verify
    uint8_t hash[64];
    trf_calculate_digest(DIGEST_TYPE_SHA256, pub_key_in, pub_sz, hash);
    char fingerprint[16];
    for(int i=0; i<4; i++) sprintf(fingerprint + i*2, "%02x", hash[i]);
    fprintf(stderr, "[DEBUG-VERIFY] Key fingerprint to verify: %s\n", fingerprint);

    int import_ret = scrypt_MlDsaImportPublicKey(key_obj, pub_key_in, pub_sz, MLDSA_LEVEL_5);
    if (import_ret != 0) {
        fprintf(stderr, "[DEBUG-VERIFY] scrypt_MlDsaImportPublicKey failed: %d\n", import_ret);
        scrypt_MlDsaKeyFree(key_obj);
        return TRF_PQC_ERR_SIG;
    }

    int ret = scrypt_MlDsaVerify(key_obj, data, len, sig_in, sig_sz);
    if (ret != 0) {
        fprintf(stderr, "[DEBUG-VERIFY] scrypt_MlDsaVerify failed: %d\n", ret);
    } else {
        fprintf(stderr, "[DEBUG-VERIFY] scrypt_MlDsaVerify SUCCESS\n");
    }
    scrypt_MlDsaKeyFree(key_obj);
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
