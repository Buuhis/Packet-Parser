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
    
    if (posix_memalign((void**)&server_pub, 64, PQC_BUFF_MAX) != 0 || 
        posix_memalign((void**)&server_priv, 64, PQC_BUFF_MAX) != 0) {
        printf("%s[FAIL] Memory allocation failed!%s\n", KRED, KNRM);
        if (server_pub) free(server_pub);
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
    if (posix_memalign((void**)&cipher_capsule, 64, PQC_BUFF_MAX) != 0 ||
        posix_memalign((void**)&s1_shared_secret, 64, 64) != 0 ||
        posix_memalign((void**)&s2_shared_secret, 64, 64) != 0) {
        printf("%s[FAIL] Memory allocation failed!%s\n", KRED, KNRM);
        free(server_pub); free(server_priv);
        if (cipher_capsule) free(cipher_capsule);
        if (s1_shared_secret) free(s1_shared_secret);
        return 1;
    }
    int capsule_sz = 0;

    // Handshake verification starts here

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

    byte tx_key[32] __attribute__((aligned(64))), rx_key[32] __attribute__((aligned(64)));
    trf_derive_session_keys(s1_shared_secret, 32, tx_key, rx_key);
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 3: TEST CHỮ KÝ SỐ (ML-DSA) - LUÔN CHẠY ĐỂ VERIFY HANDSHAKE
    // ---------------------------------------------------------
    {
        printf("[%sSTEP 3%s] Testing Digital Signature (ML-DSA)...\n", KYEL, KNRM);
        byte *dsa_pub = NULL, *dsa_priv = NULL, *sig = NULL;
        if (posix_memalign((void**)&dsa_pub, 64, PQC_BUFF_MAX) != 0 ||
            posix_memalign((void**)&dsa_priv, 64, PQC_BUFF_MAX) != 0 ||
            posix_memalign((void**)&sig, 64, PQC_BUFF_MAX) != 0) {
            printf("%s[FAIL] DSA Memory allocation failed!%s\n", KRED, KNRM);
            if (dsa_pub) free(dsa_pub);
            if (dsa_priv) free(dsa_priv);
            return 1;
        }
        int dsa_pub_sz = 0, dsa_priv_sz = 0, sig_sz = 0;
        const char* msg = "PQC_HANDSHAKE_VERIFICATION";

        if (dsa_pub && dsa_priv && sig) {
            if (trf_dsa_generate_keys(dsa_pub, &dsa_pub_sz, dsa_priv, &dsa_priv_sz) == TRF_PQC_OK) {
                if (trf_dsa_sign_payload(dsa_priv, dsa_priv_sz, (byte*)msg, strlen(msg), sig, &sig_sz) == TRF_PQC_OK) {
                    if (trf_dsa_verify_payload(dsa_pub, dsa_pub_sz, (byte*)msg, strlen(msg), sig, sig_sz) == TRF_PQC_OK) {
                        printf("%s[OK] DSA Signing & Verification Success.%s\n", KGRN, KNRM);
                    } else {
                        printf("%s[FAIL] DSA Verification failed!%s\n", KRED, KNRM);
                    }
                } else {
                    printf("%s[FAIL] DSA Signing failed!%s\n", KRED, KNRM);
                }
            } else {
                printf("%s[FAIL] DSA KeyGen failed!%s\n", KRED, KNRM);
            }
        }
        if (dsa_pub) free(dsa_pub);
        if (dsa_priv) free(dsa_priv);
        if (sig) free(sig);
        printf("\n");
    }

    // ---------------------------------------------------------
    // BƯỚC 4: TEST LAYER 4 (GCM + AAD)
    // ---------------------------------------------------------
    if (strcmp(test_mode, "l4") == 0 || strcmp(test_mode, "all") == 0) {
        printf("[%sSTEP 4%s] Testing Layer 4 Encryption (AES-GCM-256 + AAD)...\n", KYEL, KNRM);
        const char* data = "PQC_PROTECTED_TCP_PAYLOAD";
        const char* aad_header = "IP:10.0.0.1|PORT:8080"; // Giả lập Header mạng
        const char* wrong_aad = "IP:10.0.0.2|PORT:8080";   // Giả lập Header bị kẻ xấu sửa đổi

        byte *buf = NULL;
        if (posix_memalign((void**)&buf, 64, PQC_BUFF_MAX) != 0) return 1;
        int enc_len, dec_len;
        byte nonce[12] __attribute__((aligned(64)));
        trf_pqc_generate_nonce(nonce);
        
        if (buf) {
            memcpy(buf, data, strlen(data));
            
            // 4.1: Test mã hóa với AAD
            if (trf_encrypt_payload_gcm(tx_key, nonce, 12, (byte*)aad_header, strlen(aad_header), buf, strlen(data), &enc_len) == TRF_PQC_OK) {
                printf(" - Encrypted size: %d bytes (with AAD binding)\n", enc_len);

                // Lưu lại ciphertext để test 2 lần giải mã
                byte backup[PQC_BUFF_MAX];
                memcpy(backup, buf, enc_len);

                // 4.2: Giải mã với ĐÚNG AAD (Thành công)
                if (trf_decrypt_payload_gcm(tx_key, nonce, 12, (byte*)aad_header, strlen(aad_header), buf, enc_len, &dec_len) == TRF_PQC_OK) {
                    buf[dec_len] = '\0';
                    printf("%s[OK] L4 Decrypt (Correct AAD): %s%s\n", KGRN, (char*)buf, KNRM);
                } else {
                    printf("%s[FAIL] L4 Decrypt with correct AAD failed!%s\n", KRED, KNRM);
                }

                // 4.3: Giải mã với SAI AAD (Phải thất bại - Chống giả mạo Header)
                memcpy(buf, backup, enc_len); // Khôi phục ciphertext
                if (trf_decrypt_payload_gcm(tx_key, nonce, 12, (byte*)wrong_aad, strlen(wrong_aad), buf, enc_len, &dec_len) != TRF_PQC_OK) {
                    printf("%s[OK] AAD Tampering detected! (Decryption failed as expected for wrong header)%s\n", KGRN, KNRM);
                } else {
                    printf("%s[CRITICAL FAIL] L4 Decrypt accepted WRONG AAD! Security breach.%s\n", KRED, KNRM);
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
        byte hmac_key[32] __attribute__((aligned(64))), iv[16] __attribute__((aligned(64)));
        trf_pqc_generate_random_key(hmac_key, 32);
        trf_pqc_generate_random_key(iv, 16);
        
        char *l3_data = "IP_PACKET_OVER_PQC_TUNNEL";
        byte *buf = NULL;
        if (posix_memalign((void**)&buf, 64, PQC_BUFF_MAX) != 0) return 1;
        int enc_len, dec_len;
        
        if (buf) {
            memcpy(buf, l3_data, strlen(l3_data));
            if (trf_encrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buf, strlen(l3_data), &enc_len) == TRF_PQC_OK) {
                if (trf_decrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buf, enc_len, &dec_len) == TRF_PQC_OK) {
                    buf[dec_len] = '\0';
                    printf("%s[OK] L3 Decrypted: %s%s\n", KGRN, (char*)buf, KNRM);
                } else {
                    printf("%s[FAIL] L3 Decryption error.%s\n", KRED, KNRM);
                }
            } else {
                printf("%s[FAIL] L3 Encryption error.%s\n", KRED, KNRM);
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
