#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../inc/traffic_crypto.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"

void dump_hex(const char* label, const byte* data, int len) {
    printf("%s (%d bytes): ", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if (i > 0 && (i + 1) % 16 == 0) printf("\n                     ");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    const char* test_mode = (argc > 1) ? argv[1] : "all";
    
    printf("\n=== PQC STANDALONE INTEGRITY TEST (GCM-AAD ENABLED) ===\n\n");

    if (trf_pqc_init() != TRF_PQC_OK) {
        printf("%s[FAIL] PQC Initialization failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf("[INIT] PQC Library initialized successfully.\n\n");

    // ---------------------------------------------------------
    // BƯỚC 1: TEST KEM (ML-KEM-1024)
    // ---------------------------------------------------------
    byte *server_pub = NULL, *server_priv = NULL;
    byte *cipher_capsule = NULL, *s1_shared_secret = NULL, *s2_shared_secret = NULL;
    int pub_sz = 0, priv_sz = 0;
    
    posix_memalign((void**)&server_pub, 64, PQC_BUFF_MAX);
    posix_memalign((void**)&server_priv, 64, PQC_BUFF_MAX);
    
    printf("[%sSTEP 1%s] Testing Key Encapsulation (ML-KEM)...\n", KYEL, KNRM);
    if (trf_kem_generate_keys(server_pub, &pub_sz, server_priv, &priv_sz) == TRF_PQC_OK) {
        printf(" - Keys Generated (Pub: %d, Priv: %d bytes)\n", pub_sz, priv_sz);
        
        posix_memalign((void**)&cipher_capsule, 64, PQC_BUFF_MAX);
        posix_memalign((void**)&s1_shared_secret, 64, 64);
        posix_memalign((void**)&s2_shared_secret, 64, 64);
        
        int capsule_sz = 0;
        if (trf_kem_encapsulate(server_pub, pub_sz, cipher_capsule, &capsule_sz, s1_shared_secret) == TRF_PQC_OK) {
            if (trf_kem_decapsulate(server_priv, priv_sz, cipher_capsule, capsule_sz, s2_shared_secret) == TRF_PQC_OK) {
                if (memcmp(s1_shared_secret, s2_shared_secret, 32) == 0) {
                    printf("%s[OK] KEM Handshake: Shared Secrets Match.%s\n", KGRN, KNRM);
                } else {
                    printf("%s[FAIL] KEM: Shared Secrets Mismatch!%s\n", KRED, KNRM);
                }
            }
        }
    }
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 2: TEST DSA (ML-DSA-65)
    // ---------------------------------------------------------
    printf("[%sSTEP 2%s] Testing Digital Signature (ML-DSA)...\n", KYEL, KNRM);
    byte *dsa_pub = NULL, *dsa_priv = NULL, *sig = NULL;
    posix_memalign((void**)&dsa_pub, 64, PQC_BUFF_MAX);
    posix_memalign((void**)&dsa_priv, 64, PQC_BUFF_MAX);
    posix_memalign((void**)&sig, 64, PQC_BUFF_MAX);
    
    int dsa_pub_sz, dsa_priv_sz, sig_sz;
    const char* msg = "PQC_HANDSHAKE_AUTH_DATA";

    if (trf_dsa_generate_keys(dsa_pub, &dsa_pub_sz, dsa_priv, &dsa_priv_sz) == TRF_PQC_OK) {
        if (trf_dsa_sign_payload(dsa_priv, dsa_priv_sz, (byte*)msg, strlen(msg), sig, &sig_sz) == TRF_PQC_OK) {
            if (trf_dsa_verify_payload(dsa_pub, dsa_pub_sz, (byte*)msg, strlen(msg), sig, sig_sz) == TRF_PQC_OK) {
                printf("%s[OK] DSA: Sign/Verify Success.%s\n", KGRN, KNRM);
            } else {
                printf("%s[FAIL] DSA: Verification failed!%s\n", KRED, KNRM);
            }
        }
    }
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 3: TEST DATA PLANE (AES-GCM-256 with AAD)
    // ---------------------------------------------------------
    printf("[%sSTEP 3%s] Testing Data Plane (AES-GCM + AAD)...\n", KYEL, KNRM);
    byte tx_key[32] __attribute__((aligned(64))), rx_key[32] __attribute__((aligned(64)));
    trf_derive_session_keys(s1_shared_secret, 32, tx_key, rx_key);

    const char* payload = "PQC_PROTECTED_DATA_PAYLOAD";
    const char* aad_data = "SRC:192.168.1.1,DST:192.168.1.2,PORT:443";
    
    byte *buf = NULL;
    posix_memalign((void**)&buf, 64, PQC_BUFF_MAX);
    memcpy(buf, payload, strlen(payload));
    
    byte nonce[12] __attribute__((aligned(64)));
    trf_pqc_generate_nonce(nonce);
    
    int enc_len, dec_len;
    if (trf_encrypt_payload_gcm(tx_key, nonce, 12, (byte*)aad_data, strlen(aad_data), buf, strlen(payload), &enc_len) == TRF_PQC_OK) {
        printf(" - Encryption successful (%d bytes produced)\n", enc_len);
        
        // Thử giải mã với AAD ĐÚNG
        if (trf_decrypt_payload_gcm(tx_key, nonce, 12, (byte*)aad_data, strlen(aad_data), buf, enc_len, &dec_len) == TRF_PQC_OK) {
            buf[dec_len] = '\0';
            if (strcmp((char*)buf, payload) == 0) {
                printf("%s[OK] GCM-AAD: Correct Decryption & Integrity match.%s\n", KGRN, KNRM);
            }
        } else {
            printf("%s[FAIL] GCM-AAD: Decryption failed!%s\n", KRED, KNRM);
        }

        // THỬ THÁCH: Giải mã với AAD SAI (Giả lập bị tấn công sửa IP/Port)
        printf(" - Testing Integrity Protection (Tampering AAD)...\n");
        memcpy(buf, payload, strlen(payload)); // Reset buffer
        trf_encrypt_payload_gcm(tx_key, nonce, 12, (byte*)aad_data, strlen(aad_data), buf, strlen(payload), &enc_len);
        
        const char* tampered_aad = "SRC:192.168.1.1,DST:192.168.1.99,PORT:443"; // Sửa IP đích
        if (trf_decrypt_payload_gcm(tx_key, nonce, 12, (byte*)tampered_aad, strlen(tampered_aad), buf, enc_len, &dec_len) != TRF_PQC_OK) {
            printf("%s[OK] GCM-AAD: Tampered AAD detected and rejected!%s\n", KGRN, KNRM);
        } else {
            printf("%s[FAIL] GCM-AAD: Failed to detect AAD tampering!%s\n", KRED, KNRM);
        }
    }

    // Cleanup
    free(server_pub); free(server_priv);
    free(cipher_capsule); free(s1_shared_secret); free(s2_shared_secret);
    free(dsa_pub); free(dsa_priv); free(sig); free(buf);
    trf_pqc_cleanup();
    
    printf("\n=== ALL PQC TESTS COMPLETED ===\n");
    return 0;
}
