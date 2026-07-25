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
#include "pqc_vault.h"

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


int sig_pqc_handle_ipc_cli(int argc, char **argv) {
    if (argc >= 3 && (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "--retry-policy") == 0)) {
        int policy_id = atoi(argv[2]);
        int client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client_fd < 0) {
            perror("[PQC-CLI] Failed to create socket");
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("[PQC-CLI] Failed to connect to IPC server");
            close(client_fd);
            return -1;
        }

        char msg[128];
        snprintf(msg, sizeof(msg), "RETRY %d\n", policy_id);
        write(client_fd, msg, strlen(msg));

        char resp[256];
        int n = read(client_fd, resp, sizeof(resp) - 1);
        if (n > 0) {
            resp[n] = '\0';
            printf("[PQC-CLI] Server Response:\n%s\n", resp);
        } else {
            printf("[PQC-CLI] Sent retry trigger for Policy %d.\n", policy_id);
        }
        close(client_fd);
        return 0;
    }
    return -1;
}

void sig_pqc_cleanup_ipc(void) {
    unlink(IPC_SOCKET_PATH);
}

void sig_pqc_handle_gen_identity(void) {
    uint8_t dsa_pub[3000], dsa_priv[5000];
    int pub_sz, priv_sz;
    
    trf_pqc_init_global();

    printf("[PQC-GI] Generating Manual Identity (Vault Only)...\n");
    if (trf_dsa_generate_keys(dsa_pub, &pub_sz, dsa_priv, &priv_sz) == TRF_PQC_OK) {
        char *b64_priv = malloc(priv_sz * 2);
        char *b64_pub = malloc(pub_sz * 2);
        
        trf_base64_encode(dsa_priv, priv_sz, b64_priv);
        trf_base64_encode(dsa_pub, pub_sz, b64_pub);

        // Calculate 8-char fingerprint (SHA256 of public key binary)
        uint8_t hash[64];
        trf_calculate_digest(DIGEST_TYPE_SHA256, dsa_pub, pub_sz, hash);
        char fingerprint[16];
        for (int i = 0; i < 4; i++) sprintf(fingerprint + i * 2, "%02x", hash[i]);

        printf("[PQC-GI] Success! Generated Fingerprint: %s\n", fingerprint);

        // Export directly to HashiCorp Vault (Vault is the only persistent storage)
        char key_filename[64];
        snprintf(key_filename, sizeof(key_filename), "%s.key", fingerprint);
        sig_pqc_init_vault();
        if (sig_pqc_vault_write_key(VAULT_PATH_LOCAL_PUBLIC, key_filename, b64_pub) == 0 &&
            sig_pqc_vault_write_key(VAULT_PATH_LOCAL_PRIVATE, key_filename, b64_priv) == 0) {
            printf("[PQC-GI] Successfully exported identity [%s] to HashiCorp Vault (kv/PQC_Key/local_public & local_private).\n", fingerprint);
        } else {
            fprintf(stderr, "[PQC-GI] WARNING: Failed to export identity [%s] to HashiCorp Vault.\n", fingerprint);
        }
        
        free(b64_priv);
        free(b64_pub);
    } else {
        fprintf(stderr, "[PQC-GI] ERROR: Failed to generate identity keys!\n");
    }
}
