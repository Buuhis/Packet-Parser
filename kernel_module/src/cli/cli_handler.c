#include "cli/cli_handler.h"
#include "config/db_client.h"
#include "kernel_sync.h"
#include "system/cpu_tune.h"
#include "utils/logger.h"
#include "pqc_handshake.h"
#include "pqc_vault.h"
#include "../kernel/mwan_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ------------------------------------------------------------------ */
/*  Forward declarations for functions defined in main.c              */
/* ------------------------------------------------------------------ */
extern void pqc_bind_node(int node_id);
extern void save_node_id(int node_id);
extern void clear_node_id(void);

/* ================================================================== */
/*  INTERNAL: Send a JSON reply to the client fd                      */
/* ================================================================== */
static void reply_json(int fd, int code, const char *message)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"code\": %d, \"message\": \"%s\"}", code, message);
    send(fd, buf, strlen(buf), 0);
}

/* ================================================================== */
/*  INTERNAL: Client-side helper — connect to daemon socket and send  */
/* ================================================================== */
static int client_send_and_print(const char *socket_path, const char *msg)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 1;

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[-] Connection refused! Is daemon running?\n");
        close(fd);
        return 1;
    }

    send(fd, msg, strlen(msg), 0);

    char reply[512] = {0};
    int rn = recv(fd, reply, sizeof(reply) - 1, 0);
    if (rn > 0) {
        printf("%s\n", reply);
        close(fd);
        return (strstr(reply, "\"code\": 200") != NULL) ? 0 : 1;
    }

    printf("[-] No reply from daemon\n");
    close(fd);
    return 1;
}

/* ================================================================== */
/*  PUBLIC: Parse argv and handle client-mode commands                */
/*  Returns:  0 = success, 1 = error, -1 = not client mode           */
/* ================================================================== */
int cli_handle_client_args(int argc, char **argv, const char *socket_path)
{
    if (argc < 2) return -1;

    for (int i = 1; i < argc; i++) {
        /* ----- -id <node_id> ------------------------------------------------ */
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            int node_id = atoi(argv[++i]);
            if (node_id <= 0) { fprintf(stderr, "Error: Invalid ID\n"); return 1; }
            char msg[32];
            snprintf(msg, sizeof(msg), "%d", node_id);
            return client_send_and_print(socket_path, msg);
        }


        /* ----- -r <node_id> ------------------------------------------------- */
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            int node_id = atoi(argv[++i]);
            if (node_id <= 0) { fprintf(stderr, "Error: Invalid ID\n"); return 1; }
            char msg[32];
            snprintf(msg, sizeof(msg), "-r %d", node_id);
            return client_send_and_print(socket_path, msg);
        }

        /* ----- -a / --add <profile_id> <table.if_name>... ------------------- */
        if ((strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--add") == 0) && i + 2 < argc) {
            int profile_id = atoi(argv[++i]);
            if (profile_id <= 0) { fprintf(stderr, "Error: Invalid profile_id\n"); return 1; }

            char msg[1024];
            int len = snprintf(msg, sizeof(msg), "add %d", profile_id);

            i++;
            while (i < argc) {
                if (argv[i][0] == '-') {
                    break;
                }
                int n = snprintf(msg + len, sizeof(msg) - (size_t)len,
                                 " %s", argv[i]);
                if (n < 0 || (size_t)n >= sizeof(msg) - (size_t)len) {
                    break;
                }
                len += n;
                i++;
            }
            i--;

            return client_send_and_print(socket_path, msg);
        }

        /* ----- -d / --delete <profile_id> [<table.if_name>...] -------------- */
        if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delete") == 0) && i + 1 < argc) {
            int profile_id = atoi(argv[++i]);
            if (profile_id <= 0) { fprintf(stderr, "Error: Invalid profile_id\n"); return 1; }

            char msg[1024];
            int len = snprintf(msg, sizeof(msg), "del %d", profile_id);

            i++;
            while (i < argc) {
                if (argv[i][0] == '-') {
                    break;
                }
                int n = snprintf(msg + len, sizeof(msg) - (size_t)len,
                                 " %s", argv[i]);
                if (n < 0 || (size_t)n >= sizeof(msg) - (size_t)len) {
                    break;
                }
                len += n;
                i++;
            }
            i--;

            return client_send_and_print(socket_path, msg);
        }

        /* ----- -e / --edit <profile_id> <table1.field1> <table2.field2> ... --- */
        if ((strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--edit") == 0) && i + 2 < argc) {
            int profile_id = atoi(argv[++i]);
            if (profile_id <= 0) { fprintf(stderr, "Error: Invalid profile_id\n"); return 1; }
            
            char msg[1024];
            int len = snprintf(msg, sizeof(msg), "edit %d", profile_id);
            
            // Collect all remaining arguments as fields to edit
            i++;
            while (i < argc) {
                if (argv[i][0] == '-') {
                    break;
                }
                int n = snprintf(msg + len, sizeof(msg) - len, " %s", argv[i]);
                if (n < 0 || (size_t)n >= sizeof(msg) - len) {
                    break; // Buffer full
                }
                len += n;
                i++;
            }
            i--; // Adjust outer loop pointer
            
            return client_send_and_print(socket_path, msg);
        }
    }

    return -1;  /* Not a known client command */
}

/* ================================================================== */
/*  DAEMON-SIDE HANDLERS                                              */
/* ================================================================== */

static unsigned long provision_generation;

static const char *provision_mode_name(const app_config_t *cfg)
{
    if (!cfg->encrypt.enabled)
        return "BYPASS";
    if (cfg->encrypt.layer == 2 && cfg->encrypt.type == MWAN_CRYPT_PQC_GCM)
        return "L2/PQC-GCM";
    if (cfg->encrypt.layer == 3 && cfg->encrypt.type == MWAN_CRYPT_PQC_GCM)
        return "L3/PQC-GCM";
    if (cfg->encrypt.layer == 2)
        return cfg->encrypt.type == MWAN_CRYPT_AES_GCM_128 ?
               "L2/AES-GCM-128" : "L2/AES-GCM-256";
    if (cfg->encrypt.layer == 3)
        return cfg->encrypt.type == MWAN_CRYPT_AES_GCM_128 ?
               "L3/AES-GCM-128" : "L3/AES-GCM-256";
    return "INVALID";
}


/* ---------- handle: -r <node_id> ---------------------------------- */
static void handle_retry(int client_fd, int req_id)
{
    log_info(">>> Received PQC handshake retry request for Node ID: %d", req_id);
    sig_pqc_trigger_retry(req_id);
    reply_json(client_fd, 200, "Retry triggered");
}

/* ---------- handle: <node_id> (initial provisioning) -------------- */
static void handle_provision(int client_fd, int req_id, app_context_t *ctx)
{
    unsigned long generation = ++provision_generation;
    app_context_t candidate;

    log_info("[CFG-TRACE user=%lu] BEGIN -id node=%d active_node=%d active_mode=%s active_key_len=%zu active_tunnels=%zu",
             generation, req_id, ctx->cfg.node_id,
             provision_mode_name(&ctx->cfg), ctx->cfg.encrypt.key_len,
             ctx->cfg.sdwan_tun_count);

    app_config_t new_cfg;
    if (db_client_load_config(req_id, &new_cfg) != 0) {
        log_error("[CFG-TRACE user=%lu] DB_LOAD_FAILED node=%d",
                  generation, req_id);
        reply_json(client_fd, 404, "Failed to load config from DB");
        return;
    }

    log_info("[CFG-TRACE user=%lu] DB_LOADED node=%d mode=%s enabled=%d layer=%u type=%u key_len=%zu tunnels=%zu",
             generation, new_cfg.node_id, provision_mode_name(&new_cfg),
             new_cfg.encrypt.enabled, new_cfg.encrypt.layer,
             new_cfg.encrypt.type, new_cfg.encrypt.key_len,
             new_cfg.sdwan_tun_count);

    candidate.cfg = new_cfg;
    app_context_dump(&candidate);

    if (kernel_sync_push_config(&candidate) != 0) {
        log_error("[CFG-TRACE user=%lu] KERNEL_SYNC_FAILED node=%d mode=%s",
                  generation, candidate.cfg.node_id,
                  provision_mode_name(&candidate.cfg));
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    ctx->cfg = candidate.cfg;

    log_info("[CFG-TRACE user=%lu] CTX_REPLACED node=%d mode=%s key_len=%zu",
             generation, ctx->cfg.node_id, provision_mode_name(&ctx->cfg),
             ctx->cfg.encrypt.key_len);

    log_info("[CFG-TRACE user=%lu] KERNEL_SYNC_RETURNED_SUCCESS node=%d mode=%s",
             generation, ctx->cfg.node_id, provision_mode_name(&ctx->cfg));

    cpu_tune_apply(ctx);
    save_node_id(req_id);

    if (new_cfg.encrypt.enabled && new_cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        log_info("[CFG-TRACE user=%lu] PQC_HANDSHAKE_START node=%d",
                 generation, req_id);
        pqc_bind_node(req_id);
    }

    log_info("[CFG-TRACE user=%lu] END response=200 node=%d mode=%s",
             generation, ctx->cfg.node_id, provision_mode_name(&ctx->cfg));
    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: add <profile_id> <table.if_name>... ----------- */
static void handle_add_tunnels(int client_fd, int profile_id,
                               const char tunnel_names[][IFNAMSIZ],
                               size_t tunnel_count, app_context_t *ctx)
{
    app_context_t candidate = *ctx;

    for (size_t n = 0; n < tunnel_count; n++) {
        const char *tunnel_name = tunnel_names[n];
        sdwan_tun_cfg_t new_tun;

        log_info(">>> [ADD] Profile %d: adding tunnel '%s'", profile_id,
                 tunnel_name);

        if (candidate.cfg.sdwan_tun_count >= MAX_SDWAN_TUNS) {
            reply_json(client_fd, 400, "Maximum tunnel count reached");
            return;
        }

        for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
            if (strcmp(candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                       tunnel_name) == 0) {
                reply_json(client_fd, 400, "Tunnel is already active");
                return;
            }
        }

        if (db_client_load_tunnel(profile_id, tunnel_name,
                                  candidate.cfg.weight_enabled,
                                  &new_tun) != 0) {
            log_error("[ADD] Tunnel '%s' not found in DB for profile %d",
                      tunnel_name, profile_id);
            reply_json(client_fd, 404, "Tunnel not found in database");
            return;
        }

        candidate.cfg.sdwan_tuns[candidate.cfg.sdwan_tun_count++] = new_tun;
    }

    /* Sync to kernel */
    if (kernel_sync_push_config(&candidate) == 0) {
        *ctx = candidate;
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[ADD] Tunnel '%s' added and synced to kernel (total: %zu)",
                     tunnel_names[n], ctx->cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200, "Tunnel added successfully");
    } else {
        log_error("[ADD] Netlink push failed after adding tunnel '%s'",
                  tunnel_names[0]);
        reply_json(client_fd, 500, "Netlink push error");
    }
}

/* ---------- handle: del <profile_id> <table.if_name>... ----------- */
static void handle_del_tunnels(int client_fd, int profile_id,
                               const char tunnel_names[][IFNAMSIZ],
                               size_t tunnel_count, app_context_t *ctx)
{
    app_context_t candidate = *ctx;

    for (size_t n = 0; n < tunnel_count; n++) {
        const char *tunnel_name = tunnel_names[n];

        log_info(">>> [DEL] Profile %d: removing tunnel '%s'", profile_id,
                 tunnel_name);

        int found = -1;
        for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
            if (strcmp(candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                       tunnel_name) == 0) {
                found = (int)i;
                break;
            }
        }

        if (found < 0) {
            log_warn("[DEL] Tunnel '%s' not found in running config",
                     tunnel_name);
            reply_json(client_fd, 404, "Tunnel not found in running config");
            return;
        }

        /* Shift remaining elements down in the candidate only. */
        for (size_t i = (size_t)found;
             i < candidate.cfg.sdwan_tun_count - 1; i++) {
            candidate.cfg.sdwan_tuns[i] = candidate.cfg.sdwan_tuns[i + 1];
        }
        candidate.cfg.sdwan_tun_count--;
        memset(&candidate.cfg.sdwan_tuns[candidate.cfg.sdwan_tun_count], 0,
               sizeof(sdwan_tun_cfg_t));
    }

    /* Sync to kernel */
    if (kernel_sync_push_config(&candidate) == 0) {
        *ctx = candidate;
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[DEL] Tunnel '%s' removed and synced to kernel (remaining: %zu)",
                     tunnel_names[n], ctx->cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200, "Tunnel deleted successfully");
    } else {
        log_error("[DEL] Netlink push failed after removing tunnel '%s'",
                  tunnel_names[0]);
        reply_json(client_fd, 500, "Netlink push error");
    }
}

/* ---------- handle: del <profile_id> ------------------------------ */
static void handle_del_profile(int client_fd, int profile_id,
                               app_context_t *ctx)
{
    app_context_t candidate = {0};

    (void)profile_id;
    if (kernel_sync_push_config(&candidate) != 0) {
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    sig_pqc_prepare_reload();
    sig_pqc_finalize_reload();
    cpu_tune_restore();
    memset(ctx, 0, sizeof(*ctx));
    clear_node_id();
    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: edit <profile_id> <fields...> ----------------- */
static void handle_edit_config_multi(int client_fd, int profile_id, const char *fields_str, app_context_t *ctx)
{
    app_context_t candidate = *ctx;

    log_info(">>> [EDIT] Profile %d: fields changed: '%s'", profile_id, fields_str);

    bool refresh_profiles = false;
    bool refresh_tunnels = false;
    bool refresh_pqc_keys = false;
    bool refresh_pqc_tunnels = false;
    bool unknown_prefix = false;
    char unknown_name[128] = {0};

    // Duplicate the fields string because strtok modifies it
    char *fields_dup = strdup(fields_str);
    if (!fields_dup) {
        reply_json(client_fd, 500, "Out of memory");
        return;
    }

    char *token = strtok(fields_dup, " \t\r\n");
    int token_count = 0;
    while (token != NULL) {
        token_count++;
        if (strncmp(token, "sdwan_profiles.", 15) == 0) {
            refresh_profiles = true;
        } else if (strncmp(token, "sdwan_tunnels.", 14) == 0) {
            refresh_tunnels = true;
        } else if (strncmp(token, "pqc_keys.", 9) == 0) {
            refresh_pqc_keys = true;
        } else if (strncmp(token, "pqc_exchange_tunnels.", 21) == 0) {
            refresh_pqc_tunnels = true;
        } else {
            unknown_prefix = true;
            strncpy(unknown_name, token, sizeof(unknown_name) - 1);
            break;
        }
        token = strtok(NULL, " \t\r\n");
    }
    free(fields_dup);

    if (token_count == 0) {
        reply_json(client_fd, 400, "No fields specified to edit");
        return;
    }

    if (unknown_prefix) {
        log_warn("[EDIT] Unknown table prefix in '%s'", unknown_name);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "Unknown table prefix in '%s'. Use sdwan_profiles.<field>, sdwan_tunnels.<field>, pqc_keys.<field> or pqc_exchange_tunnels.<field>", unknown_name);
        reply_json(client_fd, 400, err_msg);
        return;
    }

    bool sync_needed = false;

    /* Profile weight_enable changes affect every tunnel's effective weight,
     * so profile and tunnel refreshes both reload one coherent snapshot. */
    if (refresh_profiles || refresh_tunnels) {
        app_config_t refreshed;
        if (db_client_load_config(profile_id, &refreshed) != 0) {
            reply_json(client_fd, 500, "Failed to reload profile config from DB");
            return;
        }

        /* Keep an already-derived PQC session key until the requested
         * handshake refresh below replaces it. */
        if (ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM &&
            ctx->cfg.encrypt.key_len == PQC_TRAFFIC_KEY_SZ &&
            refreshed.encrypt.type == MWAN_CRYPT_PQC_GCM) {
            memcpy(refreshed.encrypt.key, ctx->cfg.encrypt.key,
                   PQC_TRAFFIC_KEY_SZ);
            refreshed.encrypt.key_len = PQC_TRAFFIC_KEY_SZ;
        }
        candidate.cfg = refreshed;
        sync_needed = true;
    }

    // 3. Sync config to kernel if needed
    if (sync_needed) {
        if (kernel_sync_push_config(&candidate) != 0) {
            reply_json(client_fd, 500, "Netlink push error");
            return;
        }
        *ctx = candidate;
        log_info("[EDIT] Profile/tunnel config refreshed for profile %d",
                 profile_id);
        log_info("[EDIT] Config changes successfully synced to kernel");
    }

    // 4. Trigger PQC handshake if PQC encryption is active and PQC params or profiles refreshed
    bool trigger_pqc_handshake = false;
    if (ctx->cfg.encrypt.enabled && ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        if (refresh_pqc_keys || refresh_pqc_tunnels || refresh_profiles) {
            trigger_pqc_handshake = true;
        }
    }

    if (trigger_pqc_handshake) {
        log_info("[EDIT] PQC credentials/config updated — triggering key re-handshake for profile %d", profile_id);
        sig_pqc_init_vault();
        pqc_bind_node(profile_id);
    }

    reply_json(client_fd, 200, "Config updated and synced successfully");
}

#define SDWAN_TUNNEL_TOKEN_PREFIX "sdwan_tunnels."

static int parse_tunnel_command(const char *args, int *profile_id,
                                char tunnel_names[][IFNAMSIZ],
                                size_t *tunnel_count)
{
    const size_t prefix_len = strlen(SDWAN_TUNNEL_TOKEN_PREFIX);
    const char *cursor = args;
    char *endptr;
    long parsed_id;
    size_t count = 0;

    while (*cursor == ' ' || *cursor == '\t')
        cursor++;

    parsed_id = strtol(cursor, &endptr, 10);
    if (endptr == cursor || parsed_id <= 0 ||
        (*endptr != '\0' && *endptr != ' ' && *endptr != '\t'))
        return -1;
    cursor = endptr;

    while (*cursor != '\0') {
        const char *token;
        size_t token_len;
        size_t ifname_len;

        while (*cursor == ' ' || *cursor == '\t')
            cursor++;
        if (*cursor == '\0')
            break;

        token = cursor;
        token_len = strcspn(token, " \t\r\n");
        if (count >= MAX_SDWAN_TUNS || token_len <= prefix_len ||
            strncmp(token, SDWAN_TUNNEL_TOKEN_PREFIX, prefix_len) != 0)
            return -1;

        ifname_len = token_len - prefix_len;
        if (ifname_len >= IFNAMSIZ)
            return -1;

        memcpy(tunnel_names[count], token + prefix_len, ifname_len);
        tunnel_names[count][ifname_len] = '\0';
        count++;
        cursor += token_len;
    }

    *profile_id = (int)parsed_id;
    *tunnel_count = count;
    return 0;
}

/* ================================================================== */
/*  PUBLIC: Dispatch a daemon socket message to the right handler     */
/* ================================================================== */
void cli_handle_daemon_message(int client_fd, const char *buf, app_context_t *running_ctx)
{

    /* -r <id> */
    if (strncmp(buf, "-r ", 3) == 0) {
        handle_retry(client_fd, atoi(buf + 3));
        return;
    }

    /* add <profile_id> <table.if_name>... */
    if (strncmp(buf, "add ", 4) == 0) {
        int pid = 0;
        char tunnel_names[MAX_SDWAN_TUNS][IFNAMSIZ] = {{0}};
        size_t tunnel_count = 0;
        if (parse_tunnel_command(buf + 4, &pid, tunnel_names,
                                 &tunnel_count) == 0 &&
            tunnel_count > 0) {
            handle_add_tunnels(client_fd, pid, tunnel_names, tunnel_count,
                               running_ctx);
        } else {
            reply_json(client_fd, 400, "Usage: add <profile_id> <if_name>");
        }
        return;
    }

    /* del <profile_id> [<table.if_name>...] */
    if (strncmp(buf, "del ", 4) == 0) {
        int pid = 0;
        char tunnel_names[MAX_SDWAN_TUNS][IFNAMSIZ] = {{0}};
        size_t tunnel_count = 0;
        if (parse_tunnel_command(buf + 4, &pid, tunnel_names,
                                 &tunnel_count) != 0) {
            reply_json(client_fd, 400, "Usage: del <profile_id> <if_name>");
        } else if (tunnel_count == 0) {
            handle_del_profile(client_fd, pid, running_ctx);
        } else {
            handle_del_tunnels(client_fd, pid, tunnel_names, tunnel_count,
                               running_ctx);
        }
        return;
    }

    /* edit <profile_id> <fields...> */
    if (strncmp(buf, "edit ", 5) == 0) {
        int pid = 0;
        char *endptr;
        const char *p = buf + 5;
        pid = (int)strtol(p, &endptr, 10);
        if (pid <= 0 || endptr == p) {
            reply_json(client_fd, 400, "Usage: edit <profile_id> <table.field_of_table> [fields...]");
            return;
        }
        handle_edit_config_multi(client_fd, pid, endptr, running_ctx);
        return;
    }

    /* Default: numeric node_id = provisioning */
    int req_id = atoi(buf);
    if (req_id > 0) {
        handle_provision(client_fd, req_id, running_ctx);
        return;
    }

    reply_json(client_fd, 400, "Unknown command");
}
