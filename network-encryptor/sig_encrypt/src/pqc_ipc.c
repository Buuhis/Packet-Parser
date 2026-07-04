#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "pqc_ipc.h"
#include "pqc_handshake.h"
#include "traffic_crypto.h"

#define IPC_SOCKET_PATH "/var/run/test_network-encryptor.sock"

static void *ipc_listener_thread_main(void *arg) {
    (void)arg;
    unlink(IPC_SOCKET_PATH);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[IPC] socket failed");
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[IPC] bind failed");
        close(listen_fd);
        return NULL;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("[IPC] listen failed");
        close(listen_fd);
        return NULL;
    }

    chmod(IPC_SOCKET_PATH, 0660);

    fprintf(stderr, "[IPC] Listening on Unix Socket: %s\n", IPC_SOCKET_PATH);

    while (1) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            usleep(100000);
            continue;
        }

        char buf[128];
        memset(buf, 0, sizeof(buf));
        int n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            int policy_id = -1;
            if (sscanf(buf, "RETRY %d", &policy_id) == 1) {
                char resp_buf[1024];
                memset(resp_buf, 0, sizeof(resp_buf));
                sig_pqc_trigger_retry_with_info(policy_id, resp_buf, sizeof(resp_buf) - 1);
                if (write(client_fd, resp_buf, strlen(resp_buf)) < 0) {
                    perror("write");
                }
            } else {
                if (write(client_fd, "ERROR: invalid command\n", 23) < 0) {
                    perror("write");
                }
            }
        }
        close(client_fd);
    }

    close(listen_fd);
    unlink(IPC_SOCKET_PATH);
    return NULL;
}

void sig_pqc_start_ipc_server(void) {
    pthread_t ipc_thread;
    pthread_create(&ipc_thread, NULL, ipc_listener_thread_main, NULL);
    pthread_detach(ipc_thread);
}

static int run_ipc_client(int policy_id) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error: Daemon is not running (failed to connect to socket %s)\n", IPC_SOCKET_PATH);
        close(fd);
        return 1;
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "RETRY %d\n", policy_id);
    if (write(fd, cmd, strlen(cmd)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    char resp[128];
    memset(resp, 0, sizeof(resp));
    int n = read(fd, resp, sizeof(resp) - 1);
    if (n > 0) {
        printf("%s", resp);
    } else {
        fprintf(stderr, "Error: No response from daemon\n");
    }

    close(fd);
    return 0;
}

int sig_pqc_handle_ipc_cli(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            int retry_policy_id = atoi(argv[i + 1]);
            return run_ipc_client(retry_policy_id);
        }
    }
    return -1; // Not handled
}

void sig_pqc_cleanup_ipc(void) {
    unlink(IPC_SOCKET_PATH);
}

void sig_pqc_handle_gen_identity(void) {
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
        }
        free(file_priv_content);
        free(obf_priv);
        
        // Add to RAM Registry
        sig_pqc_add_to_registry(fingerprint, b64_priv, b64_pub);
        
        free(b64_priv);
        free(b64_pub);
    } else {
        fprintf(stderr, "[PQC-GI] ERROR: Failed to generate identity keys!\n");
    }
}

