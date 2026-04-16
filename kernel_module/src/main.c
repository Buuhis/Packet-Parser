#define _GNU_SOURCE
#include "app_context.h"
#include "kernel_sync.h"
#include "system/cpu_tune.h"
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
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NODE_INFO_DIR "/etc/sd-wan"
#define NODE_INFO_FILE NODE_INFO_DIR "/node.info"

/* ---------- global state ---------- */
static volatile int running_server = 1;
static int unix_server_fd = -1;
static char socket_path[256] = "/var/run/sd-wan.sock";
static app_context_t running_ctx;

/* ---------- startup config persistence ---------- */
static void save_node_id(int node_id) {
    mkdir(NODE_INFO_DIR, 0755); // Ignore error if exists
    FILE *f = fopen(NODE_INFO_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", node_id);
        fclose(f);
        log_info("Saved node_id %d to %s", node_id, NODE_INFO_FILE);
    } else {
        log_warn("Failed to write to %s", NODE_INFO_FILE);
    }
}

static int load_node_id(void) {
    FILE *f = fopen(NODE_INFO_FILE, "r");
    if (!f) return -1;
    int id = -1;
    if (fscanf(f, "%d", &id) != 1) {
        id = -1;
    }
    fclose(f);
    return id;
}

static void clear_node_id(void) {
    if (unlink(NODE_INFO_FILE) == 0) {
         printf("[+] Device has been unprovisioned. Startup config removed.\n");
    } else {
         if (errno == ENOENT) {
             printf("[!] Device is already unprovisioned.\n");
         } else {
             perror("[-] Failed to remove config");
         }
    }
}

/* ---------- utilities ---------- */
static int resolve_local_network(app_config_t *cfg) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) return -1;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (strcmp(ifa->ifa_name, cfg->local_if) == 0) {
            cfg->local_ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            cfg->local_mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            cfg->local_ip &= cfg->local_mask; // Get network address
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

/* ---------- signal handler ---------- */
static void handle_signal(int sig) {
    (void)sig;
    running_server = 0;
    cpu_tune_restore();
    kernel_sync_cleanup();
    db_client_stop_heartbeat();
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unix_server_fd = -1;
        unlink(socket_path);
    }
}

/* ---------- usage ---------- */
static void usage(const char *prog) {
    printf("=========================================================\n");
    printf("         MULTI-WAN PACKET FORWARDER (sd-wan)            \n");
    printf("=========================================================\n");
    printf("Client Mode (Control running daemon):\n");
    printf("  %s -id <node_id>    Send config request to the daemon\n", prog);
    printf("  %s -reset           Clear the node_id startup configuration\n", prog);
    printf("  %s --help | -h      Show this help message and exit\n", prog);
    printf("\n");
    printf("Daemon Mode (Start the background service):\n");
    printf("  Run without arguments to start the daemon.\n");
    printf("  Requires ENV vars: DB_HOST, DB_PORT, DB_USER, DB_NAME, [DB_PASS]\n");
    printf("=========================================================\n");
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    const char *env_sock = getenv("SDWAN_SOCKET_PATH");
    if (env_sock) strncpy(socket_path, env_sock, sizeof(socket_path)-1);
    
    log_set_level(LOG_INFO);

    int client_mode = 0, node_id = 0, reset_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 0;
        } else if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            client_mode = 1; node_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-reset") == 0) {
            reset_mode = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1;
        }
    }

    if (reset_mode) {
        clear_node_id();
        return 0;
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
        
        char reply[512] = {0};
        int rn = recv(fd, reply, sizeof(reply)-1, 0);
        if (rn > 0) {
            printf("%s\n", reply);
            close(fd);
            return (strstr(reply, "\"code\": 200") != NULL) ? 0 : 1;
        } else {
            printf("[-] No reply from daemon\n");
            close(fd); 
            return 1;
        }
    }

    /* DAEMON MODE */
    const char *db_h = getenv("POSTGRES_HOST"); 
    const char *db_p = getenv("POSTGRES_PORT"); 
    const char *db_u = getenv("POSTGRES_USER"); 
    const char *db_n = getenv("POSTGRES_TABLE");
    const char *db_pass = getenv("POSTGRES_PASS");
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

    /* Auto-load from startup config if exists */
    int saved_node_id = load_node_id();
    if (saved_node_id > 0) {
        log_info(">>> Found startup config! Auto-loading properties for Node ID: %d", saved_node_id);
        app_config_t new_cfg;
        if (db_client_load_config(saved_node_id, &new_cfg) == 0) {
            if (resolve_local_network(&new_cfg) == 0) {
                struct in_addr addr = { .s_addr = new_cfg.local_ip };
                log_info("[+] Auto-discovered Local Network: %s", inet_ntoa(addr));
            } else {
                log_warn("[-] Could not resolve local network for interface %s", new_cfg.local_if);
            }
            app_context_dump(&(app_context_t){new_cfg});
            running_ctx.cfg = new_cfg;
            if (kernel_sync_push_config(&running_ctx) != 0) {
                log_error("Failed to push auto-loaded config to kernel");
                db_client_report_error(saved_node_id, "Startup config Netlink error");
            } else {
                cpu_tune_apply(&running_ctx);
                log_info("Startup config successfully restored.");
                db_client_start_heartbeat(saved_node_id);
            }
        } else {
            log_error("Failed to load startup config from DB.");
            db_client_report_error(saved_node_id, "Failed to load config from DB");
        }
    } else {
        log_info("No startup config found. Waiting for provisioning (-id) via socket...");
    }

    while(running_server) {
        int client_fd = accept(unix_server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        char buf[128] = {0};
        int n = recv(client_fd, buf, sizeof(buf)-1, 0);
        if (n <= 0) { close(client_fd); continue; }
        
        while(n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n')) buf[--n] = '\0';
        int req_id = atoi(buf);
        log_info(">>> Received configure request for Node ID: %d", req_id);
        
        app_config_t new_cfg;
        if (db_client_load_config(req_id, &new_cfg) == 0) {
            if (resolve_local_network(&new_cfg) == 0) {
                struct in_addr addr = { .s_addr = new_cfg.local_ip };
                log_info("[+] Auto-discovered Local Network: %s", inet_ntoa(addr));
            } else {
                log_warn("[-] Could not resolve local network for interface %s", new_cfg.local_if);
            }
            
            app_context_dump(&(app_context_t){new_cfg});
            running_ctx.cfg = new_cfg;
            if (kernel_sync_push_config(&running_ctx) != 0) {
                log_error("Failed to push config to kernel");
                db_client_report_error(req_id, "Netlink push error");
                char reply[256]; snprintf(reply, sizeof(reply), "{\"code\": 500, \"message\": \"Netlink push error\"}");
                send(client_fd, reply, strlen(reply), 0);
            } else {
                cpu_tune_apply(&running_ctx);
                save_node_id(req_id);
                db_client_start_heartbeat(req_id);
                char reply[256]; snprintf(reply, sizeof(reply), "{\"code\": 200, \"message\": \"Success\"}");
                send(client_fd, reply, strlen(reply), 0);
            }
        } else {
            db_client_report_error(req_id, "Failed to load config from DB");
            char reply[256]; snprintf(reply, sizeof(reply), "{\"code\": 404, \"message\": \"Failed to load config from DB\"}");
            send(client_fd, reply, strlen(reply), 0);
        }
        close(client_fd);
    }
    
    log_info("Server shutting down...");
    db_client_stop_heartbeat();
    cpu_tune_restore();
    kernel_sync_cleanup();
    db_client_disconnect();
    if (unix_server_fd >= 0) { close(unix_server_fd); unlink(socket_path); }
    return 0;
}
