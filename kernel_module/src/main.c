#define _GNU_SOURCE
#include "app_context.h"
#include "kernel_sync.h"
#include "runtime_config.h"
#include "system/cpu_tune.h"
#include "config/db_client.h"
#include "config/vault_db_client.h"
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
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

void clear_node_id(void) {
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

/* Accept either a plain IPv4 address or an IPv4 CIDR string from the BE. */
static int normalize_ipv4(const char *input, char *output, size_t output_len,
                          uint32_t *host_order)
{
    char address[INET_ADDRSTRLEN];
    const char *slash;
    size_t len;
    struct in_addr parsed;

    if (!input || !*input || !output || output_len == 0 || !host_order)
        return -1;
    slash = strchr(input, '/');
    len = slash ? (size_t)(slash - input) : strlen(input);
    if (len == 0 || len >= sizeof(address) || len >= output_len)
        return -1;

    memcpy(address, input, len);
    address[len] = '\0';
    if (inet_pton(AF_INET, address, &parsed) != 1)
        return -1;

    memcpy(output, address, len + 1);
    *host_order = ntohl(parsed.s_addr);
    return 0;
}

/* ---------- signal handler ---------- */
static void handle_signal(int sig) {
    (void)sig;
    running_server = 0;
    cpu_tune_restore();
    kernel_sync_cleanup();
    trf_pqc_cleanup();
    if (unix_server_fd >= 0) {
        close(unix_server_fd);
        unix_server_fd = -1;
        unlink(socket_path);
    }
}

void pqc_bind_node(int node_id, uint64_t config_generation) {
    char key_id[256] = {0};
    char local_fg_db[32] = {0};
    char peer_pub_name[256] = {0};

    // Load PQC identity config from DB
    if (db_client_load_pqc_identity(node_id,
                                    key_id, sizeof(key_id),
                                    local_fg_db, sizeof(local_fg_db),
                                    peer_pub_name,
                                    sizeof(peer_pub_name)) != 0) {
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

    // Resolve WAN / PQC Exchange Tunnel info
    char local_ip[INET_ADDRSTRLEN] = "";
    char peer_ip[INET_ADDRSTRLEN] = "";
    char hs_tun_name[64] = "";
    char hs_tun_ip[64] = "";
    char hs_peer_tun_ip[64] = "";
    uint32_t local_ip_num;
    uint32_t peer_ip_num;
    int role_mode;

    if (db_client_load_pqc_exchange_tunnel(
            node_id, hs_tun_name, sizeof(hs_tun_name), hs_tun_ip,
            sizeof(hs_tun_ip), hs_peer_tun_ip,
            sizeof(hs_peer_tun_ip)) != 0) {
        log_error("[PQC-TUNNEL] Missing PQC exchange tunnel for profile %d",
                  node_id);
        return;
    }
    if (strlen(hs_tun_name) >= IFNAMSIZ || if_nametoindex(hs_tun_name) == 0) {
        log_error("[PQC-TUNNEL] Interface '%s' does not exist or exceeds IFNAMSIZ",
                  hs_tun_name);
        return;
    }
    if (normalize_ipv4(hs_tun_ip, local_ip, sizeof(local_ip),
                       &local_ip_num) < 0 ||
        normalize_ipv4(hs_peer_tun_ip, peer_ip, sizeof(peer_ip),
                       &peer_ip_num) < 0) {
        log_error("[PQC-TUNNEL] Invalid local/peer IP: '%s' / '%s'",
                  hs_tun_ip, hs_peer_tun_ip);
        return;
    }
    if (local_ip_num == peer_ip_num) {
        log_error("[PQC-TUNNEL] Local and peer tunnel IP are identical: %s",
                  local_ip);
        return;
    }
    role_mode = local_ip_num > peer_ip_num ? PQC_ROLE_INITIATOR :
                                             PQC_ROLE_RESPONDER;
    log_info("[PQC-TUNNEL] tunnel=%s local=%s peer=%s role=%s",
             hs_tun_name, local_ip, peer_ip,
             role_mode == PQC_ROLE_INITIATOR ? "INITIATOR" : "RESPONDER");

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
        sig_pqc_bind_profile(node_id, key_id, role_mode, local_ip, peer_ip,
                             local_fg, peer_fg_buf, hs_tun_name,
                             found_priv, found_pub, deobf_pub,
                             config_generation);
        
        // Start/kickoff the handshake by spinning up the background worker thread for this policy
        sig_pqc_handshake_start(node_id, hs_tun_name, peer_ip);
        
        log_info("[PQC] Handshake worker initiated for profile %d on %s (%s -> %s)",
                 node_id, hs_tun_name, local_ip, peer_ip);
    } else {
        log_error("[PQC] PQC Handshake will NOT start for Node %d due to errors.", node_id);
    }

    if (deobf_pub) free(deobf_pub);
}

void sig_pqc_on_key_ready(int profile_id, const uint8_t *key_bytes,
                          uint64_t config_generation) {
    app_context_t candidate;
    enum kernel_sync_result sync_result;

    log_info("[PQC] Handshake successful for Node %d! Syncing new dynamic session key to kernel...", profile_id);
    runtime_config_lock();
    log_info("[CFG-TRACE pqc-callback] ENTER config_generation=%llu callback_node=%d active_node=%d active_enabled=%d active_layer=%u active_type=%u active_key_len=%zu key_ptr=%s",
             (unsigned long long)config_generation, profile_id,
             running_ctx.cfg.node_id,
             running_ctx.cfg.encrypt.enabled,
             running_ctx.cfg.encrypt.layer,
             running_ctx.cfg.encrypt.type,
             running_ctx.cfg.encrypt.key_len,
             key_bytes ? "valid" : "null");
    
    // Check if this matches the currently running Node configuration
    if (key_bytes &&
        runtime_config_generation_is_current_locked(config_generation) &&
        running_ctx.cfg.node_id == profile_id &&
        running_ctx.cfg.encrypt.enabled &&
        running_ctx.cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        candidate = running_ctx;
        memcpy(candidate.cfg.encrypt.key, key_bytes, PQC_TRAFFIC_KEY_SZ);
        candidate.cfg.encrypt.key_len = PQC_TRAFFIC_KEY_SZ;
        log_info("[CFG-TRACE pqc-callback] KEY_INSTALLED callback_node=%d active_node=%d active_layer=%u active_type=%u key_len=%zu",
                 profile_id, candidate.cfg.node_id,
                 candidate.cfg.encrypt.layer,
                 candidate.cfg.encrypt.type,
                 candidate.cfg.encrypt.key_len);
        
        // Push configuration to kernel datapath via Netlink
        sync_result = kernel_sync_push_config(&candidate);
        if (sync_result == KERNEL_SYNC_APPLIED) {
            running_ctx = candidate;
            log_info("[PQC] Dynamic key synchronized with kernel datapath for Node %d", profile_id);
        } else {
            log_error("[PQC] Failed to sync dynamic key to kernel for Node %d", profile_id);
        }
    } else {
        log_warn("[CFG-TRACE pqc-callback] STALE_OR_INACTIVE config_generation=%llu callback_node=%d active_node=%d active_enabled=%d active_layer=%u active_type=%u",
                 (unsigned long long)config_generation, profile_id,
                 running_ctx.cfg.node_id,
                 running_ctx.cfg.encrypt.enabled,
                 running_ctx.cfg.encrypt.layer,
                 running_ctx.cfg.encrypt.type);
        log_warn("[PQC] Handshake key ready for Node %d but no active tunnel/encryption is configured for it.", profile_id);
    }
    runtime_config_unlock();
}

/* ---------- usage ---------- */
static void usage(const char *prog) {
    printf("=========================================================\n");
    printf("                 SD-WAN            \n");
    printf("=========================================================\n");
    printf("Client Mode (Control running daemon):\n");
    printf("  %s -id <profile_id>                    Send config request to the daemon\n", prog);
    printf("  %s -gi <node_id>                       Generate PQC identity keys for node\n", prog);
    printf("  %s -r <profile_id>                     Retry PQC handshake for profile\n", prog);
    printf("  %s -a/--add <profile_id> <tunnel_name> Add a tunnel dynamically\n", prog);
    printf("  %s -d/--delete <profile_id> <tunnel_name> Delete a tunnel dynamically\n", prog);
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
    char db_s_buf[128] = {0};
    char db_p_buf[32] = {0};
    char db_u_buf[64] = {0};
    char db_n_buf[64] = {0};
    char db_pass_buf[128] = {0};

    const char *db_h = NULL;
    const char *db_p = NULL;
    const char *db_u = NULL;
    const char *db_n = NULL;
    const char *db_pass = NULL;

    log_info("Fetching Database credentials from HashiCorp Vault (/v1/kv/data/secret)...");
    if (vault_db_fetch_config(db_s_buf, sizeof(db_s_buf),
                            db_p_buf, sizeof(db_p_buf),
                            db_u_buf, sizeof(db_u_buf),
                            db_n_buf, sizeof(db_n_buf),
                            db_pass_buf, sizeof(db_pass_buf)) == 0) {
        db_h = db_s_buf;
        db_p = db_p_buf;
        db_u = db_u_buf;
        db_n = db_n_buf;
        db_pass = db_pass_buf;
    } else {
        log_warn("Failed to fetch DB config from Vault! Falling back to Environment Variables...");
        db_h = getenv("POSTGRES_SERVER") ? getenv("POSTGRES_SERVER") : getenv("POSTGRES_HOST"); 
        db_p = getenv("POSTGRES_PORT"); 
        db_u = getenv("POSTGRES_USER"); 
        db_n = getenv("POSTGRES_DB") ? getenv("POSTGRES_DB") : getenv("POSTGRES_TABLE");
        db_pass = getenv("POSTGRES_PASSWORD") ? getenv("POSTGRES_PASSWORD") : getenv("POSTGRES_PASS");
    }

    if (!db_h || !db_p || !db_u || !db_n) {
        log_error("Missing DB connection parameters from both Vault and ENV!"); usage(argv[0]); return 1;
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
    // int saved_node_id = load_node_id();
    int saved_node_id = -1;
    if (saved_node_id > 0) {
        log_info(">>> Found startup config! Auto-loading properties for Node ID: %d", saved_node_id);
        app_config_t new_cfg;
        if (db_client_load_config(saved_node_id, &new_cfg) == 0) {
            uint64_t previous_generation;
            uint64_t config_generation = runtime_config_begin_reload(
                &previous_generation);
            enum kernel_sync_result sync_result;

            app_context_dump(&(app_context_t){new_cfg});
            runtime_config_lock();
            sync_result = kernel_sync_push_config(
                &(app_context_t){.cfg = new_cfg});
            if (sync_result == KERNEL_SYNC_ERROR) {
                runtime_config_unlock();
                runtime_config_cancel_reload(config_generation,
                                             previous_generation);
                log_error("Failed to push auto-loaded config to kernel");
            } else {
                running_ctx.cfg = new_cfg;
                runtime_config_unlock();
                cpu_tune_apply(&running_ctx);
                save_node_id(saved_node_id);
                log_info("Startup config successfully restored.");
                if (new_cfg.encrypt.enabled && new_cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
                    pqc_bind_node(saved_node_id, config_generation);
                }
            }
        } else {
            log_error("Failed to load startup config from DB.");
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
    cpu_tune_restore();
    kernel_sync_cleanup();
    db_client_disconnect();
    if (unix_server_fd >= 0) { close(unix_server_fd); unlink(socket_path); }
    return 0;
}
