#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../inc/traffic_crypto.h"

// Màu sắc cho log
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KCYN  "\x1B[36m"

// PQC Keys có thể rất lớn, cấp phát động để tránh Segfault trên Stack
// ML-KEM-1024 (Level 5) cần ~3KB, ML-DSA-87 (Level 5) cần ~5KB
#define PQC_BUFF_MAX 10240 

void print_hex(const char* label, const byte* data, int len) {
    printf("%s: ", label);
    int display_len = (len > 32) ? 32 : len;
    for (int i = 0; i < display_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *test_mode = "all";
    if (argc > 1) test_mode = argv[1];

    printf("%s====================================================\n", KCYN);
    printf("   PQC STANDALONE TEST - MODE: %s\n", test_mode);
    printf("====================================================%s\n\n", KNRM);

    // ---------------------------------------------------------
    // BƯỚC 1: KHỞI TẠO GLOBAL
    // ---------------------------------------------------------
    printf("[%sSTEP 1%s] Initializing PQC Engine...\n", KYEL, KNRM);
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        printf("%s[FAIL] PQC Initialization failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf("%s[OK] PQC Engine Ready.%s\n\n", KGRN, KNRM);

    // ---------------------------------------------------------
    // BƯỚC 2: MÔ PHỎNG BẮT TAY (ML-KEM HANDSHAKE)
    // ---------------------------------------------------------
    printf("[%sSTEP 2%s] Simulating ML-KEM Handshake...\n", KYEL, KNRM);
    
    // Cấp phát vùng nhớ lớn trên Heap thay vì Stack để tránh Segfault
    byte *server_pub = NULL, *server_priv = NULL;
    byte *cipher_capsule = NULL, *s1_shared_secret = NULL, *s2_shared_secret = NULL;
    int pub_sz = 0, priv_sz = 0;
    
    server_pub = (byte*)malloc(PQC_BUFF_MAX);
    server_priv = (byte*)malloc(PQC_BUFF_MAX);
    
    if (!server_pub || !server_priv) {
        printf("%s[FAIL] Memory allocation failed!%s\n", KRED, KNRM);
        return 1;
    }

    // Server 2 tạo cặp khóa
    if (trf_kem_generate_keys(server_pub, &pub_sz, server_priv, &priv_sz) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM KeyGen failed!%s\n", KRED, KNRM);
        free(server_pub); free(server_priv);
        return 1;
    }
    printf(" - Generated ML-KEM Keys (Pub: %d, Priv: %d bytes)\n", pub_sz, priv_sz);

    // Server 1 thực hiện Encapsulate
    cipher_capsule = (byte*)malloc(PQC_BUFF_MAX);
    s1_shared_secret = (byte*)malloc(64);
    s2_shared_secret = (byte*)malloc(64);
    int capsule_sz = 0;

    if (!cipher_capsule || !s1_shared_secret || !s2_shared_secret) {
        printf("%s[FAIL] Memory allocation failed!%s\n", KRED, KNRM);
        free(server_pub); free(server_priv);
        if (cipher_capsule) free(cipher_capsule);
        if (s1_shared_secret) free(s1_shared_secret);
        if (s2_shared_secret) free(s2_shared_secret);
        return 1;
    }

    if (trf_kem_encapsulate(server_pub, pub_sz, cipher_capsule, &capsule_sz, s1_shared_secret) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM Encapsulate failed!%s\n", KRED, KNRM);
        goto cleanup;
    }

    // Server 2 thực hiện Decapsulate
    if (trf_kem_decapsulate(server_priv, priv_sz, cipher_capsule, capsule_sz, s2_shared_secret) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM Decapsulate failed!%s\n", KRED, KNRM);
        goto cleanup;
    }

    if (memcmp(s1_shared_secret, s2_shared_secret, 32) == 0) {
        printf("%s[OK] Shared Secrets match!%s\n", KGRN, KNRM);
    } else {
        printf("%s[FAIL] Shared Secrets mismatch!%s\n", KRED, KNRM);
        free(server_pub); free(server_priv);
        return 1;
    }

    byte tx_key[32], rx_key[32];
    trf_derive_session_keys(s1_shared_secret, 32, tx_key, rx_key);
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 3: TEST CHỮ KÝ SỐ (ML-DSA)
    // ---------------------------------------------------------
    if (strcmp(test_mode, "all") == 0) {
        printf("[%sSTEP 3%s] Testing Digital Signature (ML-DSA)...\n", KYEL, KNRM);
        byte *dsa_pub = (byte*)malloc(PQC_BUFF_MAX);
        byte *dsa_priv = (byte*)malloc(PQC_BUFF_MAX);
        byte *sig = (byte*)malloc(PQC_BUFF_MAX);
        int dsa_pub_sz, dsa_priv_sz, sig_sz;
        const char* msg = "PQC_HANDSHAKE_VERIFICATION";

        if (dsa_pub && dsa_priv && sig) {
            if (trf_dsa_generate_keys(dsa_pub, &dsa_pub_sz, dsa_priv, &dsa_priv_sz) == TRF_PQC_OK) {
                if (trf_dsa_sign_payload(dsa_priv, dsa_priv_sz, (byte*)msg, strlen(msg), sig, &sig_sz) == TRF_PQC_OK) {
                    if (trf_dsa_verify_payload(dsa_pub, dsa_pub_sz, (byte*)msg, strlen(msg), sig, sig_sz) == TRF_PQC_OK) {
                        printf("%s[OK] DSA Signing & Verification Success.%s\n", KGRN, KNRM);
                    }
                }
            }
        }
        if (dsa_pub) free(dsa_pub);
        if (dsa_priv) free(dsa_priv);
        if (sig) free(sig);
        printf("\n");
    }

    // ---------------------------------------------------------
    // BƯỚC 4: TEST LAYER 4 (GCM)
    // ---------------------------------------------------------
    if (strcmp(test_mode, "l4") == 0 || strcmp(test_mode, "all") == 0) {
        printf("[%sSTEP 4%s] Testing Layer 4 Encryption (AES-GCM-256)...\n", KYEL, KNRM);
        const char* data = "PQC_PROTECTED_TCP_PAYLOAD";
        byte *buf = (byte*)malloc(PQC_BUFF_MAX);
        int enc_len, dec_len;
        byte nonce[12];
        trf_pqc_generate_nonce(nonce);
        
        if (buf) {
            memcpy(buf, data, strlen(data));
            if (trf_encrypt_payload_gcm(tx_key, nonce, 12, buf, strlen(data), &enc_len) == TRF_PQC_OK) {
                printf(" - Encrypted size: %d bytes\n", enc_len);
                if (trf_decrypt_payload_gcm(tx_key, nonce, 12, buf, enc_len, &dec_len) == TRF_PQC_OK) {
                    buf[dec_len] = '\0';
                    printf("%s[OK] L4 Decrypted: %s%s\n", KGRN, (char*)buf, KNRM);
                }
            } else {
                printf("%s[FAIL] L4 Encryption error.%s\n", KRED, KNRM);
            }
            free(buf);
        }
    }

    // ---------------------------------------------------------
    // BƯỚC 5: TEST LAYER 3 (CBC+HMAC)
    // ---------------------------------------------------------
    if (strcmp(test_mode, "l3") == 0 || strcmp(test_mode, "all") == 0) {
        printf("[%sSTEP 5%s] Testing Layer 3 Encryption (CBC+HMAC)...\n", KYEL, KNRM);
        byte hmac_key[32], iv[16];
        trf_pqc_generate_random_key(hmac_key, 32);
        trf_pqc_generate_random_key(iv, 16);
        
        char *l3_data = "IP_PACKET_OVER_PQC_TUNNEL";
        byte *buf = (byte*)malloc(PQC_BUFF_MAX);
        int enc_len, dec_len;
        
        if (buf) {
            memcpy(buf, l3_data, strlen(l3_data));
            if (trf_encrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buf, strlen(l3_data), &enc_len) == TRF_PQC_OK) {
                if (trf_decrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buf, enc_len, &dec_len) == TRF_PQC_OK) {
                    buf[dec_len] = '\0';
                    printf("%s[OK] L3 Decrypted: %s%s\n", KGRN, (char*)buf, KNRM);
                }
            }
            free(buf);
        }
    }

    printf("\n%s[DONE] Standalone test finished.%s\n", KCYN, KNRM);

cleanup:
    if (server_pub) free(server_pub);
    if (server_priv) free(server_priv);
    if (cipher_capsule) free(cipher_capsule);
    if (s1_shared_secret) free(s1_shared_secret);
    if (s2_shared_secret) free(s2_shared_secret);
    
    trf_pqc_cleanup();
    return 0;
}
