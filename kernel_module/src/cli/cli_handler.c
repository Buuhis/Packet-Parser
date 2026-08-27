#include "cli/cli_handler.h"
#include "config/db_client.h"
#include "kernel_sync.h"
#include "runtime_config.h"
#include "system/cpu_tune.h"
#include "utils/logger.h"
#include "pqc_handshake.h"
#include "pqc_vault.h"
#include "../kernel/mwan_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ------------------------------------------------------------------ */
/*  Forward declarations for functions defined in main.c              */
/* ------------------------------------------------------------------ */
extern int pqc_bind_node(int node_id, uint64_t config_generation);
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
            snprintf(msg, sizeof(msg), "-id %d", node_id);
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

        /* ----- -gs / --get-status <data_tunnel_interface> ------------------ */
        if (strcmp(argv[i], "-gs") == 0 ||
            strcmp(argv[i], "--get-status") == 0) {
            size_t ifname_len;
            char msg[32];

            if (i + 1 >= argc || i + 2 != argc) {
                fprintf(stderr,
                        "Error: Usage: -gs/--get-status <interface>\n");
                return 1;
            }
            ifname_len = strnlen(argv[i + 1], IFNAMSIZ);
            if (ifname_len == 0 || ifname_len >= IFNAMSIZ) {
                fprintf(stderr, "Error: Invalid tunnel interface\n");
                return 1;
            }
            snprintf(msg, sizeof(msg), "get-status %s", argv[i + 1]);
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

/* Report the BFD-published state currently enforced by kernel steering. */
static void handle_get_status(int client_fd, const char *ifname,
                              app_context_t *ctx)
{
    bool active_tunnel = false;
    bool up = false;
    int rc;

    runtime_config_lock();
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        if (strcmp(ctx->cfg.sdwan_tuns[i].tunnel_ifname, ifname) == 0) {
            active_tunnel = true;
            break;
        }
    }
    runtime_config_unlock();

    if (!active_tunnel) {
        reply_json(client_fd, 404,
                   "Tunnel not found in running configuration");
        return;
    }

    rc = kernel_sync_get_tunnel_status(ifname, &up);
    if (rc == 0) {
        reply_json(client_fd, 200, up ? "UP" : "DOWN");
    } else if (rc == -ENODEV) {
        reply_json(client_fd, 503,
                   "Kernel module or tunnel interface unavailable");
    } else {
        log_warn("[GET-STATUS] Failed to query state for tunnel %s: %s",
                 ifname, strerror(-rc));
        reply_json(client_fd, 500, "Failed to query tunnel status");
    }
}

static enum kernel_sync_result apply_candidate(app_context_t *ctx,
                                               const app_context_t *candidate)
{
    enum kernel_sync_result result;

    runtime_config_lock();
    result = kernel_sync_push_config(candidate);
    if (result != KERNEL_SYNC_ERROR)
        *ctx = *candidate;
    runtime_config_unlock();
    return result;
}

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

static void log_provision_snapshot(unsigned long request_id,
                                   const char *stage,
                                   const app_config_t *cfg)
{
    if (!cfg)
        return;

    log_info("[CFG-AUDIT req=%lu stage=%s] PROFILE node=%d mode=%s enabled=%d layer=%u type=%u key_len=%zu weight=%d latency=%d/%d loss=%d/%d tunnels=%zu",
             request_id, stage, cfg->node_id, provision_mode_name(cfg),
             cfg->encrypt.enabled, cfg->encrypt.layer, cfg->encrypt.type,
             cfg->encrypt.key_len, cfg->weight_enabled,
             cfg->latency_enabled, cfg->latency_duration,
             cfg->loss_enabled, cfg->loss_duration,
             cfg->sdwan_tun_count);

    for (size_t i = 0; i < cfg->sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &cfg->sdwan_tuns[i];

        log_info("[CFG-AUDIT req=%lu stage=%s] TUNNEL slot=%zu name=%s physical=%s ip=%s segment=%d weight=%d latency=%s/%d/%d loss=%s/%d/%d",
                 request_id, stage, i, tun->tunnel_ifname,
                 tun->physical_ifname, tun->tunnel_ip, tun->segment_id,
                 tun->weight, tun->latency_ip, tun->latency,
                 tun->latency_enabled, tun->loss_ip,
                 tun->loss_percentage, tun->loss_enabled);
    }
}


/* ---------- handle: -r <node_id> ---------------------------------- */
static void handle_retry(int client_fd, int req_id, app_context_t *ctx)
{
    char retry_info[320] = {0};
    app_context_t active;
    uint64_t config_generation;
    int retry_rc;

    log_info(">>> Received PQC handshake retry request for Node ID: %d", req_id);

    runtime_config_lock();
    active = *ctx;
    runtime_config_unlock();
    if (active.cfg.node_id != req_id || !active.cfg.encrypt.enabled ||
        active.cfg.encrypt.type != MWAN_CRYPT_PQC_GCM) {
        snprintf(retry_info, sizeof(retry_info),
                 "Profile ID %d has no active PQC configuration; run -id first",
                 req_id);
        log_warn("[PQC-HS] Retry rejected for profile %d: %s", req_id,
                 retry_info);
        reply_json(client_fd, 404, retry_info);
        return;
    }

    /* A retry is a full control-plane recovery: query DB/Vault again, replace
     * stale credentials, stop the previous attempt, and start a clean worker. */
    config_generation = runtime_config_current_generation();
    retry_rc = pqc_bind_node(req_id, config_generation);
    if (retry_rc == 0) {
        log_info("[PQC-HS] Profile %d credentials reloaded and runtime restarted",
                 req_id);
        reply_json(client_fd, 200, "Retry triggered");
        return;
    }

    snprintf(retry_info, sizeof(retry_info),
             "Profile %d retry failed: %s", req_id, strerror(-retry_rc));
    log_warn("[PQC-HS] Retry rejected for profile %d: %s", req_id,
             retry_info);
    reply_json(client_fd, 503, retry_info);
}

/* ---------- handle: <node_id> (initial provisioning) -------------- */
static void handle_provision(int client_fd, int req_id, app_context_t *ctx)
{
    unsigned long generation = ++provision_generation;
    app_context_t active_snapshot;
    app_context_t candidate;
    enum kernel_sync_result sync_result;
    uint64_t previous_config_generation;
    uint64_t config_generation;

    runtime_config_lock();
    active_snapshot = *ctx;
    runtime_config_unlock();
    log_info("[CFG-TRACE user=%lu] BEGIN -id node=%d active_node=%d active_mode=%s active_key_len=%zu active_tunnels=%zu",
             generation, req_id, active_snapshot.cfg.node_id,
             provision_mode_name(&active_snapshot.cfg),
             active_snapshot.cfg.encrypt.key_len,
             active_snapshot.cfg.sdwan_tun_count);
    log_provision_snapshot(generation, "BEFORE", &active_snapshot.cfg);

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
    log_provision_snapshot(generation, "DB", &new_cfg);

    candidate.cfg = new_cfg;
    app_context_dump(&candidate);

    config_generation = runtime_config_begin_reload(
        &previous_config_generation);
    log_info("[CFG-AUDIT req=%lu] CONFIG_GENERATION=%llu previous=%llu",
             generation, (unsigned long long)config_generation,
             (unsigned long long)previous_config_generation);
    sync_result = apply_candidate(ctx, &candidate);
    if (sync_result == KERNEL_SYNC_ERROR) {
        runtime_config_cancel_reload(config_generation,
                                     previous_config_generation);
        log_error("[CFG-TRACE user=%lu] KERNEL_SYNC_FAILED node=%d mode=%s",
                  generation, candidate.cfg.node_id,
                  provision_mode_name(&candidate.cfg));
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    log_info("[CFG-TRACE user=%lu] CTX_REPLACED node=%d mode=%s key_len=%zu",
             generation, ctx->cfg.node_id, provision_mode_name(&ctx->cfg),
             ctx->cfg.encrypt.key_len);

    log_info("[CFG-TRACE user=%lu] KERNEL_SYNC_RETURNED_SUCCESS node=%d mode=%s",
             generation, ctx->cfg.node_id, provision_mode_name(&ctx->cfg));
    log_info("[CFG-AUDIT req=%lu] SYNC_RESULT=%s node=%d mode=%s",
             generation,
             sync_result == KERNEL_SYNC_APPLIED ? "APPLIED" : "DEFERRED",
             ctx->cfg.node_id, provision_mode_name(&ctx->cfg));
    log_provision_snapshot(generation, "USERSPACE_ACTIVE", &ctx->cfg);

    cpu_tune_apply(ctx);
    save_node_id(req_id);

    sig_pqc_prepare_reload();
    sig_pqc_finalize_reload();

    if (new_cfg.encrypt.enabled && new_cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        int pqc_rc;

        log_info("[CFG-TRACE user=%lu] PQC_HANDSHAKE_START node=%d",
                 generation, req_id);
        pqc_rc = pqc_bind_node(req_id, config_generation);
        if (pqc_rc != 0) {
            log_warn("[CFG-TRACE user=%lu] PQC_HANDSHAKE_DEFERRED node=%d error=%s",
                     generation, req_id, strerror(-pqc_rc));
        }
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
    app_context_t candidate;

    runtime_config_lock();
    candidate = *ctx;

    for (size_t n = 0; n < tunnel_count; n++) {
        const char *tunnel_name = tunnel_names[n];
        sdwan_tun_cfg_t new_tun;

        log_info(">>> [ADD] Profile %d: adding tunnel '%s'", profile_id,
                 tunnel_name);

        if (candidate.cfg.sdwan_tun_count >= MAX_SDWAN_TUNS) {
            runtime_config_unlock();
            reply_json(client_fd, 400, "Maximum tunnel count reached");
            return;
        }

        for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
            if (strcmp(candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                       tunnel_name) == 0) {
                runtime_config_unlock();
                reply_json(client_fd, 400, "Tunnel is already active");
                return;
            }
        }

        if (db_client_load_tunnel(profile_id, tunnel_name,
                                  candidate.cfg.weight_enabled,
                                  &new_tun) != 0) {
            runtime_config_unlock();
            log_error("[ADD] Tunnel '%s' not found in DB for profile %d",
                      tunnel_name, profile_id);
            reply_json(client_fd, 404, "Tunnel not found in database");
            return;
        }

        candidate.cfg.sdwan_tuns[candidate.cfg.sdwan_tun_count++] = new_tun;
    }

    /* Sync to kernel */
    if (kernel_sync_push_config(&candidate) != KERNEL_SYNC_ERROR) {
        *ctx = candidate;
        runtime_config_unlock();
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[ADD] Tunnel '%s' added and synced to kernel (total: %zu)",
                     tunnel_names[n], candidate.cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200, "Tunnel added successfully");
    } else {
        runtime_config_unlock();
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
    app_context_t candidate;

    runtime_config_lock();
    candidate = *ctx;

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
            runtime_config_unlock();
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
    if (kernel_sync_push_config(&candidate) != KERNEL_SYNC_ERROR) {
        *ctx = candidate;
        runtime_config_unlock();
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[DEL] Tunnel '%s' removed and synced to kernel (remaining: %zu)",
                     tunnel_names[n], candidate.cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200, "Tunnel deleted successfully");
    } else {
        runtime_config_unlock();
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
    uint64_t previous_config_generation;
    uint64_t config_generation;

    (void)profile_id;
    config_generation = runtime_config_begin_reload(
        &previous_config_generation);
    if (apply_candidate(ctx, &candidate) == KERNEL_SYNC_ERROR) {
        runtime_config_cancel_reload(config_generation,
                                     previous_config_generation);
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    sig_pqc_prepare_reload();
    sig_pqc_finalize_reload();
    cpu_tune_restore();
    clear_node_id();
    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: edit <profile_id> <fields...> ----------------- */
static void handle_edit_config_multi(int client_fd, int profile_id, const char *fields_str, app_context_t *ctx)
{
    app_context_t candidate;
    uint64_t previous_config_generation = 0;
    uint64_t config_generation = 0;

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
    bool reload_pqc_lifecycle = refresh_profiles || refresh_pqc_keys ||
                                refresh_pqc_tunnels;
    bool trigger_pqc_handshake = false;

    if (reload_pqc_lifecycle)
        config_generation = runtime_config_begin_reload(
            &previous_config_generation);

    runtime_config_lock();
    candidate = *ctx;

    /* Profile weight_enable changes affect every tunnel's effective weight,
     * so profile and tunnel refreshes both reload one coherent snapshot. */
    if (refresh_profiles || refresh_tunnels) {
        app_config_t refreshed;
        if (db_client_load_config(profile_id, &refreshed) != 0) {
            runtime_config_unlock();
            if (reload_pqc_lifecycle)
                runtime_config_cancel_reload(config_generation,
                                             previous_config_generation);
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
        if (kernel_sync_push_config(&candidate) == KERNEL_SYNC_ERROR) {
            runtime_config_unlock();
            if (reload_pqc_lifecycle)
                runtime_config_cancel_reload(config_generation,
                                             previous_config_generation);
            reply_json(client_fd, 500, "Netlink push error");
            return;
        }
        *ctx = candidate;
        log_info("[EDIT] Profile/tunnel config refreshed for profile %d",
                 profile_id);
        log_info("[EDIT] Config changes successfully synced to kernel");
    }

    // 4. Trigger PQC handshake if PQC encryption is active and PQC params or profiles refreshed
    if (ctx->cfg.encrypt.enabled && ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        if (refresh_pqc_keys || refresh_pqc_tunnels || refresh_profiles) {
            trigger_pqc_handshake = true;
        }
    }
    runtime_config_unlock();

    if (reload_pqc_lifecycle) {
        sig_pqc_prepare_reload();
        sig_pqc_finalize_reload();
    }

    if (trigger_pqc_handshake) {
        int pqc_rc;

        log_info("[EDIT] PQC credentials/config updated — triggering key re-handshake for profile %d", profile_id);
        sig_pqc_init_vault();
        pqc_rc = pqc_bind_node(profile_id, config_generation);
        if (pqc_rc != 0) {
            log_warn("[EDIT] PQC handshake deferred for profile %d: %s",
                     profile_id, strerror(-pqc_rc));
        }
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

    /* get-status <data_tunnel_interface> */
    if (strncmp(buf, "get-status ", 11) == 0) {
        const char *ifname = buf + 11;
        size_t ifname_len = strnlen(ifname, IFNAMSIZ);

        if (ifname_len == 0 || ifname_len >= IFNAMSIZ ||
            ifname[ifname_len] != '\0' || strpbrk(ifname, " \t\r\n")) {
            reply_json(client_fd, 400,
                       "Usage: get-status <interface>");
            return;
        }
        handle_get_status(client_fd, ifname, running_ctx);
        return;
    }

    /* -id <profile_id>: always perform a full DB reload, even when a
     * configuration is already active. */
    if (strncmp(buf, "-id ", 4) == 0) {
        char *endptr;
        long parsed_id = strtol(buf + 4, &endptr, 10);

        while (*endptr == ' ' || *endptr == '\t')
            endptr++;
        if (parsed_id <= 0 || *endptr != '\0') {
            reply_json(client_fd, 400, "Unknown command");
            return;
        }

        log_info("[CLI-AUDIT] RECEIVED command=-id profile=%ld",
                 parsed_id);
        handle_provision(client_fd, (int)parsed_id, running_ctx);
        return;
    }

    /* -r <id> */
    if (strncmp(buf, "-r ", 3) == 0) {
        handle_retry(client_fd, atoi(buf + 3), running_ctx);
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

    /* Backward compatibility with older clients that sent only node_id. */
    int req_id = atoi(buf);
    if (req_id > 0) {
        handle_provision(client_fd, req_id, running_ctx);
        return;
    }

    reply_json(client_fd, 400, "Unknown command");
}
