#define _GNU_SOURCE
#include "app_context.h"
#include "kernel_sync.h"
#include "config/db_client.h"
#include "utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ---------- global state ---------- */
static volatile int running_server = 1;
static int unix_server_fd = -1;
static char socket_path[256] = "/var/run/sep-wan.sock";
static app_context_t running_ctx;

/* ---------- signal handler ---------- */
static void handle_signal(int sig) {
    (void)sig;
    running_server = 0;
    kernel_sync_cleanup();
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unix_server_fd = -1;
        unlink(socket_path);
    }
}

/* ---------- usage ---------- */
static void usage(const char *prog) {
    printf("=========================================================\n");
    printf("         MULTI-WAN PACKET FORWARDER (sep-wan)            \n");
    printf("=========================================================\n");
    printf("Client Mode (Control running daemon):\n");
    printf("  %s -id <node_id>    Send config request to the daemon\n", prog);
    printf("  %s --help | -h      Show this help message and exit\n", prog);
    printf("\n");
    printf("Daemon Mode (Start the background service):\n");
    printf("  Run without arguments to start the daemon.\n");
    printf("  Requires ENV vars: DB_HOST, DB_PORT, DB_USER, DB_NAME, [DB_PASS]\n");
    printf("=========================================================\n");
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    const char *env_sock = getenv("MWAN_SOCKET_PATH");
    if (env_sock) strncpy(socket_path, env_sock, sizeof(socket_path)-1);
    
    log_set_level(LOG_INFO);

    int client_mode = 0, node_id = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 0;
        } else if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            client_mode = 1; node_id = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1;
        }
    }

    if (client_mode) {
        if (node_id <= 0) {
            fprintf(stderr, "Error: Invalid ID\n"); return 1;
        }
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return 1;
        struct sockaddr_un addr = {.sun_family = AF_UNIX};
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "[-] Connection refused! Is daemon running?\n"); close(fd); return 1;
        }
        char id_str[16]; snprintf(id_str, sizeof(id_str), "%d", node_id);
        send(fd, id_str, strlen(id_str), 0);
        printf("[+] Command sent successfully! Node ID: %d\n", node_id);
        close(fd); return 0;
    }

    /* DAEMON MODE */
    const char *db_h = getenv("DB_HOST"), *db_p = getenv("DB_PORT"), *db_u = getenv("DB_USER"), *db_n = getenv("DB_NAME"), *db_pass = getenv("DB_PASS");
    if (!db_h || !db_p || !db_u || !db_n) {
        log_error("Missing DB ENV vars"); usage(argv[0]); return 1;
    }

    if (db_client_connect(db_h, db_p, db_u, db_n, db_pass) != 0) {
        log_error("Failed to connect to DB! Exiting."); return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    unix_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_server_fd < 0) return 1;
    unlink(socket_path);
    struct sockaddr_un saddr = {.sun_family = AF_UNIX};
    strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path)-1);
    if (bind(unix_server_fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0 || listen(unix_server_fd, 5) < 0) {
        log_error("Socket bind/listen failed"); return 1;
    }
    
    log_info("Control Plane Ready! Socket: %s", socket_path);

    while(running_server) {
        int client_fd = accept(unix_server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        char buf[128] = {0};
        int n = recv(client_fd, buf, sizeof(buf)-1, 0);
        close(client_fd);
        if (n <= 0) continue;
        while(n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n')) buf[--n] = '\0';
        int req_id = atoi(buf);
        log_info(">>> Received configure request for Node ID: %d", req_id);
        
        app_config_t new_cfg;
        if (db_client_load_config(req_id, &new_cfg) == 0) {
            app_context_dump(&(app_context_t){new_cfg});
            running_ctx.cfg = new_cfg;
            if (kernel_sync_push_config(&running_ctx) != 0) log_error("Failed to push config to kernel");
        }
    }
    
    log_info("Server shutting down...");
    kernel_sync_cleanup();
    db_client_disconnect();
    if (unix_server_fd >= 0) { close(unix_server_fd); unlink(socket_path); }
    return 0;
}
