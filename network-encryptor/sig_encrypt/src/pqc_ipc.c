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
                sig_pqc_trigger_retry(policy_id);
                if (write(client_fd, "SUCCESS\n", 8) < 0) {
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
