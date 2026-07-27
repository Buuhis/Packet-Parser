#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>

#include "inc/traffic_crypto.h"
#include "inc/pqc_vault.h"

#define PQC_KEYGEN_SOCKET_PATH "/var/run/pqc_keygen.sock"

static volatile int g_daemon_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_daemon_running = 0;
    unlink(PQC_KEYGEN_SOCKET_PATH);
    exit(0);
}

static int run_keygen_task(char *out_fg, size_t fg_max) {
    uint8_t dsa_pub[3000], dsa_priv[5000];
    int pub_sz = 0, priv_sz = 0;

    if (trf_dsa_generate_keys(dsa_pub, &pub_sz, dsa_priv, &priv_sz) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-DAEMON] ERROR: Failed to generate ML-DSA keys!\n");
        return -1;
    }

    char *b64_priv = malloc(priv_sz * 2);
    char *b64_pub = malloc(pub_sz * 2);
    if (!b64_priv || !b64_pub) {
        if (b64_priv) free(b64_priv);
        if (b64_pub) free(b64_pub);
        return -1;
    }

    trf_base64_encode(dsa_priv, priv_sz, b64_priv);
    trf_base64_encode(dsa_pub, pub_sz, b64_pub);

    // Calculate 8-char fingerprint (SHA-256 of public key binary)
    uint8_t hash[64];
    trf_calculate_digest(DIGEST_TYPE_SHA256, dsa_pub, pub_sz, hash);
    char fingerprint[16] = "";
    for (int i = 0; i < 4; i++) sprintf(fingerprint + i * 2, "%02x", hash[i]);

    char key_filename[64];
    snprintf(key_filename, sizeof(key_filename), "%s.key", fingerprint);

    sig_pqc_init_vault();
    int r1 = sig_pqc_vault_write_key(VAULT_PATH_LOCAL_PUBLIC, key_filename, b64_pub);
    int r2 = sig_pqc_vault_write_key(VAULT_PATH_LOCAL_PRIVATE, key_filename, b64_priv);

    free(b64_priv);
    free(b64_pub);

    if (r1 == 0 && r2 == 0) {
        snprintf(out_fg, fg_max, "%s", fingerprint);
        return 0;
    }

    return -1;
}

static int run_daemon(void) {
    unlink(PQC_KEYGEN_SOCKET_PATH);

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[PQC-DAEMON] Failed to create socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PQC_KEYGEN_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[PQC-DAEMON] Failed to bind socket");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("[PQC-DAEMON] Failed to listen on socket");
        close(server_fd);
        return 1;
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    trf_pqc_init_global();
    sig_pqc_init_vault();

    fprintf(stderr, "[PQC-DAEMON] Service listening on %s...\n", PQC_KEYGEN_SOCKET_PATH);

    while (g_daemon_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("[PQC-DAEMON] Accept failed");
            continue;
        }

        char buf[128] = "";
        int n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            if (strncmp(buf, "GEN_KEY", 7) == 0) {
                char fg[16] = "";
                if (run_keygen_task(fg, sizeof(fg)) == 0) {
                    char resp[128];
                    snprintf(resp, sizeof(resp), "OK:%s\n", fg);
                    write(client_fd, resp, strlen(resp));
                } else {
                    const char *err_resp = "ERROR:Failed to write key to Vault\n";
                    write(client_fd, err_resp, strlen(err_resp));
                }
            } else {
                const char *err_resp = "ERROR:Unknown command\n";
                write(client_fd, err_resp, strlen(err_resp));
            }
        }
        close(client_fd);
    }

    close(server_fd);
    unlink(PQC_KEYGEN_SOCKET_PATH);
    return 0;
}

static int run_cli_client(void) {
    int client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
        fprintf(stderr, "[PQC-GI] ERROR: PQC Service is not running! (pqc.service is stopped)\n");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PQC_KEYGEN_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[PQC-GI] ERROR: PQC Service is not running! (pqc.service is stopped)\n");
        close(client_fd);
        return 1;
    }

    const char *cmd = "GEN_KEY\n";
    if (write(client_fd, cmd, strlen(cmd)) < 0) {
        perror("[PQC-GI] Failed to send command to service");
        close(client_fd);
        return 1;
    }

    char resp[256] = "";
    int n = read(client_fd, resp, sizeof(resp) - 1);
    close(client_fd);

    if (n > 0) {
        resp[n] = '\0';
        if (strncmp(resp, "OK:", 3) == 0) {
            char fingerprint[16] = "";
            strncpy(fingerprint, resp + 3, 8);
            fingerprint[8] = '\0';
            // Strip newline if present
            fingerprint[strcspn(fingerprint, "\r\n")] = '\0';

            printf("[PQC-GI] Public Key Exported: kv/PQC_Key/local_public/%s.key\n", fingerprint);
            printf("[PQC-GI] Successfully exported identity [%s] to HashiCorp Vault (kv/PQC_Key/local_public & local_private).\n", fingerprint);
            return 0;
        } else {
            fprintf(stderr, "[PQC-GI] ERROR from Service: %s\n", resp);
            return 1;
        }
    }

    fprintf(stderr, "[PQC-GI] ERROR: No response received from PQC Service.\n");
    return 1;
}

static void show_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s --daemon  # Start PQC keygen daemon in background\n", prog);
    printf("  %s -gi       # Trigger key generation (requires active pqc.service)\n", prog);
}

int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "--daemon") == 0) {
            return run_daemon();
        } else if (strcmp(argv[1], "-gi") == 0) {
            return run_cli_client();
        }
    }

    show_usage(argv[0]);
    return 1;
}
