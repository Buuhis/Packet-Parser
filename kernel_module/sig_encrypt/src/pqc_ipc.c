#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pqc_ipc.h"
#include "pqc_handshake.h"
#include "traffic_crypto.h"

int sig_pqc_handle_gen_identity(char *out_fingerprint) {
    uint8_t dsa_pub[3000], dsa_priv[5000];
    int pub_sz, priv_sz;
    
    trf_pqc_init_global();
    mkdir("/etc/.enc_config", 0755);
    mkdir("/dev/shm/.enc_config", 0755);
    mkdir("/etc/.dec_config", 0755);

    printf("[PQC-GI] Generating Manual Identity (RAM-ONLY)...\n");
    if (trf_dsa_generate_keys(dsa_pub, &pub_sz, dsa_priv, &priv_sz) == TRF_PQC_OK) {
        char *b64_priv = malloc(priv_sz * 2);
        char *b64_pub = malloc(pub_sz * 2);
        
        trf_base64_encode(dsa_priv, priv_sz, b64_priv);

        // Calculate 8-char fingerprint (SHA256 of public key binary)
        uint8_t hash[64];
        trf_calculate_digest(DIGEST_TYPE_SHA256, dsa_pub, pub_sz, hash);
        char fingerprint[16];
        for(int i=0; i<4; i++) sprintf(fingerprint + i*2, "%02x", hash[i]);
        if (out_fingerprint) {
            strcpy(out_fingerprint, fingerprint);
        }

        // Obfuscate public key with its fingerprint before saving
        trf_base64_encode_obfuscated(dsa_pub, pub_sz, fingerprint, b64_pub);

        char pub_path[256];
        snprintf(pub_path, sizeof(pub_path), "/etc/.enc_config/%s.key", fingerprint);
        
        char *file_pub_content = malloc(strlen(b64_pub) + 16);
        sprintf(file_pub_content, "%s%s", fingerprint, b64_pub);

        if (trf_save_key_to_file(pub_path, file_pub_content, 0644) == 0) {
            printf("[PQC-GI] Success! Fingerprint: %s\n", fingerprint);
            printf("[PQC-GI] Public Key Exported: %s\n", pub_path);
        } else {
            fprintf(stderr, "[PQC-GI] ERROR: Failed to save key to %s\n", pub_path);
            free(file_pub_content);
            free(b64_priv);
            free(b64_pub);
            return -1;
        }
        free(file_pub_content);

        // Securely export the private key locally in RAM-disk (/dev/shm) for Zero-Trace persistence
        char priv_path[256];
        snprintf(priv_path, sizeof(priv_path), "/dev/shm/.enc_config/%s.key", fingerprint);
        char *obf_priv = malloc(priv_sz * 2 + 128);
        trf_base64_encode_obfuscated(dsa_priv, priv_sz, fingerprint, obf_priv);
        
        char *file_priv_content = malloc(strlen(obf_priv) + 16);
        sprintf(file_priv_content, "%s%s", fingerprint, obf_priv);

        if (trf_save_key_to_file(priv_path, file_priv_content, 0600) == 0) {
            printf("[PQC-GI] Secure Private Key Exported locally: %s\n", priv_path);
        } else {
            fprintf(stderr, "[PQC-GI] ERROR: Failed to save private key securely to %s\n", priv_path);
            free(file_priv_content);
            free(obf_priv);
            free(b64_priv);
            free(b64_pub);
            return -1;
        }
        free(file_priv_content);
        free(obf_priv);
        
        // Add to RAM Registry
        sig_pqc_add_to_registry(fingerprint, b64_priv, b64_pub);
        
        free(b64_priv);
        free(b64_pub);
        return 0;
    } else {
        fprintf(stderr, "[PQC-GI] ERROR: Failed to generate identity keys!\n");
        return -1;
    }
}
