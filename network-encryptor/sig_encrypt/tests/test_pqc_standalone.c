#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../inc/traffic_crypto.h"

// Màu sắc cho log
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

void print_hex(const char* label, const byte* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("%s====================================================\n", KCYN);
    printf("   PQC STANDALONE TEST - L2/L3/L4 INTEGRATION\n");
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
    printf("[%sSTEP 2%s] Simulating ML-KEM Handshake (Server1 <-> Server2)...\n", KYEL, KNRM);
    
    byte server_pub[2048], server_priv[2048];
    int pub_sz, priv_sz;
    
    // Server 2 tạo cặp khóa
    if (trf_kem_generate_keys(server_pub, &pub_sz, server_priv, &priv_sz) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM KeyGen failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf(" - Server2 generated ML-KEM Level 3 Keys (Pub: %d bytes)\n", pub_sz);

    // Server 1 thực hiện Encapsulate dựa trên PubKey của Server 2
    byte cipher_capsule[2048], s1_shared_secret[64], s2_shared_secret[64];
    int capsule_sz;
    if (trf_kem_encapsulate(server_pub, pub_sz, cipher_capsule, &capsule_sz, s1_shared_secret) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM Encapsulate failed!%s\n", KRED, KNRM);
        return 1;
    }

    // Server 2 thực hiện Decapsulate
    if (trf_kem_decapsulate(server_priv, priv_sz, cipher_capsule, capsule_sz, s2_shared_secret) != TRF_PQC_OK) {
        printf("%s[FAIL] KEM Decapsulate failed!%s\n", KRED, KNRM);
        return 1;
    }

    // Kiểm tra Shared Secret có khớp không
    if (memcmp(s1_shared_secret, s2_shared_secret, 32) == 0) {
        printf("%s[OK] Shared Secrets match! Quantum-safe tunnel established.%s\n", KGRN, KNRM);
    } else {
        printf("%s[FAIL] Shared Secrets mismatch! Handshake failed.%s\n", KRED, KNRM);
        return 1;
    }

    // Sinh Session Key AES-256 qua HKDF
    byte tx_key[32], rx_key[32];
    if (trf_derive_session_keys(s1_shared_secret, 32, tx_key, rx_key) != TRF_PQC_OK) {
        printf("%s[FAIL] HKDF Expansion failed!%s\n", KRED, KNRM);
        return 1;
    }
    print_hex(" - Derived TX Session Key", tx_key, 32);
    print_hex(" - Derived RX Session Key", rx_key, 32);
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 3: TEST CHỮ KÝ SỐ (ML-DSA)
    // ---------------------------------------------------------
    printf("[%sSTEP 3%s] Testing Digital Signature (ML-DSA Level 3)...\n", KYEL, KNRM);
    byte dsa_pub[5120], dsa_priv[5120], sig[5120];
    int dsa_pub_sz, dsa_priv_sz, sig_sz;
    const char* msg = "CONFIG_ID_30_VALIDATION_TOKEN";

    if (trf_dsa_generate_keys(dsa_pub, &dsa_pub_sz, dsa_priv, &dsa_priv_sz) != TRF_PQC_OK) {
        printf("%s[FAIL] DSA KeyGen failed!%s\n", KRED, KNRM);
        return 1;
    }

    if (trf_dsa_sign_payload(dsa_priv, dsa_priv_sz, (byte*)msg, strlen(msg), sig, &sig_sz) != TRF_PQC_OK) {
        printf("%s[FAIL] DSA Signing failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf(" - Signature generated: %d bytes\n", sig_sz);

    if (trf_dsa_verify_payload(dsa_pub, dsa_pub_sz, (byte*)msg, strlen(msg), sig, sig_sz) != TRF_PQC_OK) {
        printf("%s[FAIL] DSA Verification failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf("%s[OK] DSA Verification successful! Identity confirmed.%s\n\n", KGRN, KNRM);

    // ---------------------------------------------------------
    // BƯỚC 4: TEST MÃ HÓA LAYER 4 (Payload Encryption)
    // ---------------------------------------------------------
    printf("[%sSTEP 4%s] Testing Layer 4 Encryption (AES-GCM-256)...\n", KYEL, KNRM);
    
    const char* original_payload = "SECRET_DATA_FROM_CLIENT_1_TO_CLIENT_2";
    int payload_len = strlen(original_payload);
    
    // Chuẩn bị buffer (cần tailroom cho GCM Tag 16 bytes)
    byte buffer[1024];
    memcpy(buffer, original_payload, payload_len);
    
    byte nonce[12];
    trf_pqc_generate_nonce(nonce);
    
    int encrypted_len = 0;
    if (trf_encrypt_payload_gcm(tx_key, nonce, 12, buffer, payload_len, &encrypted_len) != TRF_PQC_OK) {
        printf("%s[FAIL] L4 Encryption failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf(" - Payload encrypted. New length: %d (Orig: %d + Tag: 16)\n", encrypted_len, payload_len);

    // Giải mã
    int decrypted_len = 0;
    if (trf_decrypt_payload_gcm(tx_key, nonce, 12, buffer, encrypted_len, &decrypted_len) != TRF_PQC_OK) {
        printf("%s[FAIL] L4 Decryption failed! (Integrity Check Failed)%s\n", KRED, KNRM);
        return 1;
    }
    buffer[decrypted_len] = '\0'; // Null terminate for printing

    if (strcmp((char*)buffer, original_payload) == 0) {
        printf("%s[OK] L4 Round-trip successful! Data is intact.%s\n", KGRN, KNRM);
    } else {
        printf("%s[FAIL] L4 Data corruption detected!%s\n", KRED, KNRM);
        return 1;
    }
    printf("\n");

    // ---------------------------------------------------------
    // BƯỚC 5: TEST MÃ HÓA LAYER 3 (CBC + HMAC)
    // ---------------------------------------------------------
    printf("[%sSTEP 5%s] Testing Layer 3 Encryption (AES-CBC-256 + HMAC-SHA256)...\n", KYEL, KNRM);
    
    byte hmac_key[32];
    trf_pqc_generate_random_key(hmac_key, 32); 
    
    memcpy(buffer, original_payload, payload_len);
    byte iv[16];
    trf_pqc_generate_random_key(iv, 16);

    if (trf_encrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buffer, payload_len, &encrypted_len) != TRF_PQC_OK) {
        printf("%s[FAIL] L3 Encryption failed!%s\n", KRED, KNRM);
        return 1;
    }
    printf(" - L3 Encrypted. New length: %d (Orig: %d + HMAC-Tag: 32)\n", encrypted_len, payload_len);

    if (trf_decrypt_cbc_hmac(tx_key, hmac_key, iv, 16, buffer, encrypted_len, &decrypted_len) != TRF_PQC_OK) {
        printf("%s[FAIL] L3 Decryption/MAC verification failed!%s\n", KRED, KNRM);
        return 1;
    }
    
    if (decrypted_len == payload_len && memcmp(buffer, original_payload, payload_len) == 0) {
        printf("%s[OK] L3 Round-trip successful!%s\n", KGRN, KNRM);
    } else {
        printf("%s[FAIL] L3 Data corruption!%s\n", KRED, KNRM);
        return 1;
    }

    printf("\n%s====================================================\n", KGRN);
    printf("   ALL PQC CRYPTO TESTS PASSED SUCCESSFULLY!\n");
    printf("====================================================%s\n", KNRM);

    trf_pqc_cleanup();
    return 0;
}
