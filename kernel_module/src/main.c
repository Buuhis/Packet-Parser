#define _GNU_SOURCE
#include "app_context.h"
#include "kernel_sync.h"
#include "system/cpu_tune.h"
#include "config/db_client.h"
#include "utils/logger.h"
#include "cli/cli_handler.h"
#include "pqc_handshake.h"
#include "pqc_logger.h"
#include "pqc_vault.h"
#include "traffic_crypto.h"
#include "../kernel/mwan_proto.h"

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
void save_node_id(int node_id) {
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
    trf_pqc_cleanup();
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unix_server_fd = -1;
        unlink(socket_path);
    }
}

void pqc_bind_node(int node_id) {
    char local_fg_db[32] = {0};
    char peer_pub_name[256] = {0};

    // Load PQC identity config from DB
    if (db_client_load_pqc_identity(node_id, local_fg_db, peer_pub_name) != 0) {
        log_warn("[PQC] No PQC configuration or database identity found for Node ID: %d", node_id);
        return;
    }

    char local_fg[16] = {0};
    strncpy(local_fg, local_fg_db, 8);
    local_fg[8] = '\0';

    char local_key_name[64];
    snprintf(local_key_name, sizeof(local_key_name), "%s.key", local_fg);

    // Initialize Vault and load local identity keypair from Vault into RAM registry
    sig_pqc_init_vault();
    sig_pqc_load_key_from_vault(local_key_name);

    // Resolve WAN info from the active tunnels configured in running_ctx
    char peer_ip[64] = "0.0.0.0";
    const char *wan_ifname = "";
    if (running_ctx.cfg.ne_tunnel_count > 0) {
        peer_ip[0] = '\0';
        strncpy(peer_ip, running_ctx.cfg.ne_tunnels[0].gateway, sizeof(peer_ip) - 1);
        wan_ifname = running_ctx.cfg.ne_tunnels[0].ifname;
    }

    // Read peer public key 100% directly from HashiCorp Vault (remote_public)
    char peer_fg_buf[16] = "";
    char *deobf_pub = NULL;
    bool valid = true;

    char vault_peer_pub_buf[8192] = "";
    if (peer_pub_name[0] != '\0' &&
        sig_pqc_vault_read_key(VAULT_PATH_REMOTE_PUBLIC, peer_pub_name, vault_peer_pub_buf, sizeof(vault_peer_pub_buf)) == 0) {
        log_info("[PQC-VAULT] SUCCESS: Loaded peer public key [%s] 100%% directly from HashiCorp Vault.", peer_pub_name);
        deobf_pub = strdup(vault_peer_pub_buf);
        strncpy(peer_fg_buf, peer_pub_name, 8);
        peer_fg_buf[8] = '\0';
    } else {
        log_error("[PQC-VAULT] ERROR: Node %d peer_pub key [%s] NOT found in HashiCorp Vault (remote_public)!", node_id, peer_pub_name);
        valid = false;
    }

    char *found_priv = NULL;
    char *found_pub = NULL;
    if (valid) {
        sig_pqc_find_identity(local_fg, &found_priv, &found_pub);
        if (!found_priv || !found_pub) {
            log_error("[PQC] ERROR: Local keys for fingerprint [%s] (Node %d) not loaded in memory registry!", local_fg, node_id);
            valid = false;
        }
    }

    if (valid) {
        // We use PQC_ROLE_DYNAMIC (2) to negotiate the handshake role automatically
        sig_pqc_bind_profile(node_id, 2, peer_ip, local_fg, peer_fg_buf, wan_ifname, found_priv, found_pub, deobf_pub);
        
        // Start/kickoff the handshake by spinning up the background worker thread for this policy
        sig_pqc_handshake_start(node_id, wan_ifname, peer_ip);
        
        log_info("[PQC] Handshake worker initiated for Node %d on WAN %s to Peer IP %s", node_id, wan_ifname, peer_ip);
    } else {
        log_error("[PQC] PQC Handshake will NOT start for Node %d due to errors.", node_id);
    }

    if (deobf_pub) free(deobf_pub);
}

void sig_pqc_on_key_ready(int profile_id, const uint8_t *key_bytes) {
    log_info("[PQC] Handshake successful for Node %d! Syncing new dynamic session key to kernel...", profile_id);
    
    // Check if this matches the currently running Node configuration
    if (running_ctx.cfg.node_id == profile_id && running_ctx.cfg.encrypt.enabled) {
        // Copy the dynamic key to the active configuration
        memcpy(running_ctx.cfg.encrypt.key, key_bytes, PQC_TRAFFIC_KEY_SZ);
        running_ctx.cfg.encrypt.key_len = PQC_TRAFFIC_KEY_SZ;
        
        // Push configuration to kernel datapath via Netlink
        if (kernel_sync_push_config(&running_ctx) == 0) {
            log_info("[PQC] Dynamic key synchronized with kernel datapath for Node %d", profile_id);
        } else {
            log_error("[PQC] Failed to sync dynamic key to kernel for Node %d", profile_id);
        }
    } else {
        log_warn("[PQC] Handshake key ready for Node %d but no active tunnel/encryption is configured for it.", profile_id);
    }
}

/* ---------- usage ---------- */
static void usage(const char *prog) {
    printf("=========================================================\n");
    printf("                 SD-WAN            \n");
    printf("=========================================================\n");
    printf("Client Mode (Control running daemon):\n");
    printf("  %s -id <node_id>                       Send config request to the daemon\n", prog);
    printf("  %s -gi <node_id>                       Generate PQC identity keys for node\n", prog);
    printf("  %s -r <node_id>                        Retry PQC handshake for node\n", prog);
    printf("  %s -a/--add <profile_id> <if_name>     Add a tunnel dynamically\n", prog);
    printf("  %s -d/--delete <profile_id> <if_name>  Delete a tunnel dynamically\n", prog);
    printf("  %s -e/--edit <profile_id> <table.field> Edit a config field\n", prog);
    printf("  %s -reset                              Clear the node_id startup configuration\n", prog);
    printf("  %s --help | -h                         Show this help message and exit\n", prog);
    printf("\n");
    printf("Daemon Mode (Start the background service):\n");
    printf("  Run without arguments to start the daemon.\n");
    printf("  Requires ENV vars: DB_HOST, DB_PORT, DB_USER, DB_NAME, [DB_PASS]\n");
    printf("=========================================================\n");
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    log_set_level(LOG_INFO);

    /* Handle --help / -h first */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 0;
        }
    }

    /* Handle -reset */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-reset") == 0) {
            clear_node_id();
            return 0;
        }
    }

    /* Delegate client-mode commands to cli_handler */
    int cli_result = cli_handle_client_args(argc, argv, socket_path);
    if (cli_result >= 0) {
        return cli_result;
    }

    /* ======================== DAEMON MODE ======================== */
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

    // Initialize global PQC crypto library resources
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        log_error("Failed to initialize PQC cryptography! Exiting.");
        return 1;
    }

    // Load PQC identities from disk
    sig_pqc_init_vault();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    unix_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_server_fd < 0) return 1;
    unlink(socket_path);
    struct sockaddr_un saddr = {.sun_family = AF_UNIX};
    snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", socket_path);
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
                save_node_id(saved_node_id);
                log_info("Startup config successfully restored.");
                db_client_start_heartbeat(saved_node_id);
                if (new_cfg.encrypt.enabled && new_cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
                    pqc_bind_node(saved_node_id);
                }
            }
        } else {
            log_error("Failed to load startup config from DB.");
            db_client_report_error(saved_node_id, "Failed to load config from DB");
        }
    } else {
        log_info("No startup config found. Waiting for provisioning (-id) via socket...");
    }

    /* ======================== MAIN LOOP ======================== */
    while(running_server) {
        int client_fd = accept(unix_server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        char buf[256] = {0};
        int n = recv(client_fd, buf, sizeof(buf)-1, 0);
        if (n <= 0) { close(client_fd); continue; }
        
        while(n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n')) buf[--n] = '\0';

        /* Delegate all message handling to cli_handler */
        cli_handle_daemon_message(client_fd, buf, &running_ctx);

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
