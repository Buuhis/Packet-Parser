#include "cli/cli_handler.h"
#include "config/config_semantics.h"
#include "config/db_client.h"
#include "failover.h"
#include "kernel_sync.h"
#include "config/provision_reconcile.h"
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

        /* ----- -gpi / --get-peer-ip <data_tunnel_interface> --------------- */
        if (strcmp(argv[i], "-gpi") == 0 ||
            strcmp(argv[i], "--get-peer-ip") == 0) {
            size_t ifname_len;
            char msg[32];

            if (i + 1 >= argc || i + 2 != argc) {
                fprintf(stderr,
                        "Error: Usage: -gpi/--get-peer-ip <interface>\n");
                return 1;
            }
            ifname_len = strnlen(argv[i + 1], IFNAMSIZ);
            if (ifname_len == 0 || ifname_len >= IFNAMSIZ ||
                strpbrk(argv[i + 1], " \t\r\n")) {
                fprintf(stderr, "Error: Invalid data tunnel interface\n");
                return 1;
            }
            snprintf(msg, sizeof(msg), "get-peer-ip %s", argv[i + 1]);
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

/* Report the peer tunnel IPv4 address learned by discovery for one configured
 * SD-WAN data tunnel. Physical/WAN interfaces are deliberately rejected. */
static void handle_get_peer_ip(int client_fd, const char *ifname,
                               app_context_t *ctx)
{
    bool data_tunnel = false;
    char peer_ip[INET_ADDRSTRLEN] = {0};
    int rc;

    runtime_config_lock();
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        if (strcmp(ctx->cfg.sdwan_tuns[i].tunnel_ifname, ifname) == 0) {
            data_tunnel = true;
            break;
        }
    }
    runtime_config_unlock();

    if (!data_tunnel) {
        reply_json(client_fd, 404,
                   "Data tunnel not found in running configuration");
        return;
    }

    rc = kernel_sync_get_tunnel_peer(ifname, peer_ip, sizeof(peer_ip));
    if (rc == 0) {
        reply_json(client_fd, 200, peer_ip);
    } else if (rc == -EAGAIN) {
        reply_json(client_fd, 503,
                   "Peer tunnel IP is not resolved yet");
    } else if (rc == -ENODEV || rc == -ENOENT) {
        reply_json(client_fd, 503,
                   "Kernel module or data tunnel interface unavailable");
    } else {
        log_warn("[GET-PEER-IP] Failed to query peer IP for tunnel %s: %s",
                 ifname, strerror(-rc));
        reply_json(client_fd, 500,
                   "Failed to query peer tunnel IP");
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
    app_context_t pending;
    enum provision_transaction_kind pending_kind;
    uint64_t config_generation;
    int retry_rc;

    log_info(">>> Received PQC handshake retry request for Node ID: %d", req_id);

    runtime_config_lock();
    active = *ctx;
    runtime_config_unlock();
    if (provision_transaction_snapshot(req_id, &pending, &pending_kind,
                                       &config_generation, NULL) &&
        pending.cfg.encrypt.enabled &&
        pending.cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        retry_rc = pqc_bind_node(req_id, config_generation);
        if (retry_rc == 0) {
            log_info("[PQC-HS] Pending %s for profile %d restarted",
                     pending_kind == PROVISION_TX_FULL_APPLY ?
                         "full apply" : "security edit",
                     req_id);
            reply_json(client_fd, 200, "Pending handshake retry triggered");
            return;
        }
        snprintf(retry_info, sizeof(retry_info),
                 "Profile %d pending retry failed: %s", req_id,
                 strerror(-retry_rc));
        reply_json(client_fd, 503, retry_info);
        return;
    }
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
    if (kernel_sync_set_datapath_blocked(true) != 0) {
        runtime_config_cancel_reload(config_generation,
                                     previous_config_generation);
        log_error("[CFG-TRACE user=%lu] DATAPATH_GATE_FAILED node=%d",
                  generation, req_id);
        reply_json(client_fd, 500, "Failed to close datapath for full apply");
        return;
    }

    /* Full -id is fail-closed.  Keep running_ctx as ACTIVE and retain the DB
     * snapshot separately as PENDING until handshake + kernel ACK commit it. */
    provision_reconcile_accept(&candidate);
    provision_transaction_stage(PROVISION_TX_FULL_APPLY, &candidate,
                                config_generation,
                                previous_config_generation);
    sync_result = kernel_sync_push_config(&candidate);
    if (sync_result == KERNEL_SYNC_ERROR) {
        provision_transaction_cancel(config_generation);
        if (active_snapshot.cfg.node_id > 0)
            provision_reconcile_accept(&active_snapshot);
        else
            provision_reconcile_clear();
        (void)kernel_sync_set_datapath_blocked(false);
        runtime_config_cancel_reload(config_generation,
                                     previous_config_generation);
        log_error("[CFG-TRACE user=%lu] KERNEL_SYNC_FAILED node=%d mode=%s",
                  generation, candidate.cfg.node_id,
                  provision_mode_name(&candidate.cfg));
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    if (sync_result == KERNEL_SYNC_APPLIED) {
        runtime_config_lock();
        *ctx = candidate;
        runtime_config_unlock();
        provision_reconcile_accept(&candidate);
        provision_transaction_finish(config_generation);
        log_info("[CFG-TRACE user=%lu] COMMIT_ACTIVE node=%d mode=%s key_len=%zu",
                 generation, candidate.cfg.node_id,
                 provision_mode_name(&candidate.cfg),
                 candidate.cfg.encrypt.key_len);
    } else {
        log_info("[CFG-TRACE user=%lu] PENDING_FULL_APPLY node=%d mode=%s key_len=%zu",
                 generation, candidate.cfg.node_id,
                 provision_mode_name(&candidate.cfg),
                 candidate.cfg.encrypt.key_len);
    }

    log_info("[CFG-TRACE user=%lu] KERNEL_SYNC_RETURNED_SUCCESS node=%d mode=%s",
             generation, candidate.cfg.node_id,
             provision_mode_name(&candidate.cfg));
    log_info("[CFG-AUDIT req=%lu] SYNC_RESULT=%s node=%d mode=%s",
             generation,
             sync_result == KERNEL_SYNC_APPLIED ? "APPLIED" : "DEFERRED",
             candidate.cfg.node_id, provision_mode_name(&candidate.cfg));
    log_provision_snapshot(generation,
                           sync_result == KERNEL_SYNC_APPLIED ?
                               "USERSPACE_ACTIVE" : "USERSPACE_PENDING",
                           &candidate.cfg);

    if (sync_result == KERNEL_SYNC_APPLIED)
        cpu_tune_apply(&candidate);
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
             generation, candidate.cfg.node_id,
             provision_mode_name(&candidate.cfg));
    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: add <profile_id> <table.if_name>... ----------- */
static void rollback_add_acknowledgements(
    int profile_id, const char tunnel_names[][IFNAMSIZ], size_t tunnel_count,
    const bool changed[], const bool added[])
{
    while (tunnel_count > 0) {
        size_t n = --tunnel_count;

        if (changed[n])
            provision_reconcile_rollback_tunnel(
                profile_id, tunnel_names[n], added[n]);
    }
}

static void handle_add_tunnels(int client_fd, int profile_id,
                               const char tunnel_names[][IFNAMSIZ],
                               size_t tunnel_count, app_context_t *ctx)
{
    app_context_t candidate;
    enum provision_transaction_kind transaction_kind = PROVISION_TX_NONE;
    uint64_t transaction_generation = 0;
    bool ack_changed[MAX_SDWAN_TUNS] = { false };
    bool ack_added[MAX_SDWAN_TUNS] = { false };
    bool reconcile_needed = false;
    bool committed_full_apply = false;

    runtime_config_lock();
    if (provision_transaction_snapshot(profile_id, &candidate,
                                       &transaction_kind,
                                       &transaction_generation, NULL)) {
        if (transaction_kind != PROVISION_TX_FULL_APPLY) {
            runtime_config_unlock();
            reply_json(client_fd, 409,
                       "Security transition is still pending");
            return;
        }
    } else {
        candidate = *ctx;
    }
    if (candidate.cfg.node_id <= 0 ||
        candidate.cfg.node_id != profile_id ||
        provision_reconcile_validate_profile(profile_id) != 0) {
        runtime_config_unlock();
        log_warn("[ADD] Rejected profile=%d active_profile=%d: profile is not provisioned",
                 profile_id, candidate.cfg.node_id);
        reply_json(client_fd, 409,
                   "Profile is not provisioned or is not active");
        return;
    }

    for (size_t n = 0; n < tunnel_count; n++) {
        const char *tunnel_name = tunnel_names[n];
        sdwan_tun_cfg_t new_tun;

        log_info(">>> [ADD] Profile %d: adding tunnel '%s'", profile_id,
                 tunnel_name);

        bool already_desired = false;

        for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
            if (strcmp(candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                       tunnel_name) == 0) {
                already_desired = true;
                break;
            }
        }

        /* -id may have accepted this DB tunnel before its net_device was
         * created.  In that case -a is the explicit BE event that retries
         * only the desired snapshot; it is not a duplicate configuration. */
        if (already_desired) {
            bool was_acknowledged =
                provision_reconcile_tunnel_acknowledged(profile_id,
                                                         tunnel_name);

            if (provision_reconcile_ack_tunnel(profile_id,
                                               tunnel_name) != 0) {
                rollback_add_acknowledgements(profile_id, tunnel_names,
                                              n, ack_changed, ack_added);
                runtime_config_unlock();
                reply_json(client_fd, 503,
                           "Tunnel interface is not available yet");
                return;
            }
            ack_changed[n] = !was_acknowledged;
            reconcile_needed |= ack_changed[n];
            if (ack_changed[n])
                log_info("[ADD] Tunnel '%s' was waiting for its interface; reconciling it without restarting peer tunnels",
                         tunnel_name);
            continue;
        }

        if (candidate.cfg.sdwan_tun_count >= MAX_SDWAN_TUNS) {
            rollback_add_acknowledgements(profile_id, tunnel_names, n,
                                          ack_changed, ack_added);
            runtime_config_unlock();
            reply_json(client_fd, 400, "Maximum tunnel count reached");
            return;
        }

        if (db_client_load_tunnel(profile_id, tunnel_name,
                                  candidate.cfg.weight_enabled,
                                  &new_tun) != 0) {
            rollback_add_acknowledgements(profile_id, tunnel_names, n,
                                          ack_changed, ack_added);
            runtime_config_unlock();
            log_error("[ADD] Tunnel '%s' not found in DB for profile %d",
                      tunnel_name, profile_id);
            reply_json(client_fd, 404, "Tunnel not found in database");
            return;
        }

        if (provision_reconcile_ack_tunnel(profile_id,
                                           tunnel_name) != 0) {
            rollback_add_acknowledgements(profile_id, tunnel_names, n,
                                          ack_changed, ack_added);
            runtime_config_unlock();
            reply_json(client_fd, 503,
                       "Tunnel interface is not available yet");
            return;
        }
        ack_changed[n] = true;
        ack_added[n] = true;
        reconcile_needed = true;

        candidate.cfg.sdwan_tuns[candidate.cfg.sdwan_tun_count++] = new_tun;
    }

    if (!reconcile_needed) {
        runtime_config_unlock();
        reply_json(client_fd, 200, "Tunnel is already active");
        return;
    }

    /* Adding a tunnel changes the complete percentage snapshot. Refresh the
     * weights (and associated tunnel fields) of every active member so an
     * old 100% runtime snapshot is never combined with only the new row. */
    for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
        sdwan_tun_cfg_t refreshed;

        if (db_client_load_tunnel(
                profile_id, candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                candidate.cfg.weight_enabled, &refreshed) != 0) {
            rollback_add_acknowledgements(profile_id, tunnel_names,
                                          tunnel_count, ack_changed,
                                          ack_added);
            runtime_config_unlock();
            log_error("[ADD] Failed to refresh complete tunnel snapshot");
            reply_json(client_fd, 500,
                       "Failed to reload tunnel configuration");
            return;
        }
        candidate.cfg.sdwan_tuns[i] = refreshed;
    }
    if (!config_weights_valid(&candidate.cfg)) {
        rollback_add_acknowledgements(profile_id, tunnel_names,
                                      tunnel_count, ack_changed, ack_added);
        runtime_config_unlock();
        log_error("[ADD] Refusing invalid weight snapshot for profile %d",
                  profile_id);
        reply_json(client_fd, 400, "Invalid tunnel weight snapshot");
        return;
    }

    /* Sync to kernel */
    enum kernel_sync_result sync_result = kernel_sync_push_config(&candidate);
    if (sync_result != KERNEL_SYNC_ERROR) {
        if (transaction_kind == PROVISION_TX_FULL_APPLY) {
            if (provision_transaction_update(
                    &candidate, transaction_generation) != 0) {
                rollback_add_acknowledgements(profile_id, tunnel_names,
                                              tunnel_count, ack_changed,
                                              ack_added);
                runtime_config_unlock();
                reply_json(client_fd, 409,
                           "Full apply transaction changed; retry add");
                return;
            }
            if (sync_result == KERNEL_SYNC_APPLIED) {
                *ctx = candidate;
                provision_reconcile_accept(ctx);
                provision_transaction_finish(transaction_generation);
                committed_full_apply = true;
            }
        } else {
            *ctx = candidate;
            provision_reconcile_accept(ctx);
        }
        runtime_config_unlock();
        if (committed_full_apply)
            cpu_tune_apply(&candidate);
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[ADD] Tunnel '%s' added and synced to kernel (total: %zu)",
                     tunnel_names[n], candidate.cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200,
                   sync_result == KERNEL_SYNC_APPLIED ?
                       "Tunnel added successfully" :
                       "Tunnel accepted; waiting for PQC key");
    } else {
        rollback_add_acknowledgements(profile_id, tunnel_names,
                                      tunnel_count, ack_changed, ack_added);
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
    enum provision_transaction_kind transaction_kind = PROVISION_TX_NONE;
    enum kernel_sync_result sync_result;
    uint64_t transaction_generation = 0;
    bool transaction_pending;
    bool committed_full_apply = false;
    size_t already_absent = 0;

    runtime_config_lock();
    transaction_pending = provision_transaction_snapshot(
        profile_id, &candidate, &transaction_kind,
        &transaction_generation, NULL);
    if (transaction_pending) {
        if (transaction_kind != PROVISION_TX_FULL_APPLY) {
            runtime_config_unlock();
            reply_json(client_fd, 409,
                       "Security transition is still pending");
            return;
        }
    } else {
        /* A transaction for another profile must not be bypassed by deleting
         * from the active snapshot. */
        if (provision_transaction_any()) {
            runtime_config_unlock();
            reply_json(client_fd, 409,
                       "Another apply/security transition is still pending");
            return;
        }
        candidate = *ctx;
    }

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
            /* Delete is idempotent.  The userspace snapshot may already have
             * dropped this tunnel while the active kernel snapshot still
             * owns its net_device reference.  Keep the candidate unchanged
             * and push it below so the kernel can destroy any stale binding. */
            already_absent++;
            log_warn("[DEL] Tunnel '%s' already absent from running config; reconciling kernel snapshot",
                     tunnel_name);
            continue;
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

    /* The UI/BE stores percentages for the post-delete tunnel set. Reload
     * every remaining row before validating the new complete snapshot. */
    for (size_t i = 0; i < candidate.cfg.sdwan_tun_count; i++) {
        sdwan_tun_cfg_t refreshed;

        if (db_client_load_tunnel(
                profile_id, candidate.cfg.sdwan_tuns[i].tunnel_ifname,
                candidate.cfg.weight_enabled, &refreshed) != 0) {
            runtime_config_unlock();
            log_error("[DEL] Failed to refresh complete tunnel snapshot");
            reply_json(client_fd, 500,
                       "Failed to reload tunnel configuration");
            return;
        }
        candidate.cfg.sdwan_tuns[i] = refreshed;
    }
    if (!config_weights_valid(&candidate.cfg)) {
        runtime_config_unlock();
        log_error("[DEL] Refusing invalid weight snapshot for profile %d",
                  profile_id);
        reply_json(client_fd, 400, "Invalid tunnel weight snapshot");
        return;
    }

    /* Always reconcile the complete snapshot, including the idempotent case
     * where every requested tunnel was already absent in userspace.  Success
     * means the active kernel config was acknowledged, not merely deferred. */
    sync_result = kernel_sync_push_config(&candidate);
    if (sync_result == KERNEL_SYNC_APPLIED) {
        if (transaction_pending &&
            provision_transaction_update(
                &candidate, transaction_generation) != 0) {
            runtime_config_unlock();
            reply_json(client_fd, 409,
                       "Full apply transaction changed; retry delete");
            return;
        }
        *ctx = candidate;
        provision_reconcile_accept(ctx);
        if (transaction_pending) {
            provision_transaction_finish(transaction_generation);
            committed_full_apply = true;
        }
        runtime_config_unlock();
        if (committed_full_apply)
            cpu_tune_apply(&candidate);
        for (size_t n = 0; n < tunnel_count; n++) {
            log_info("[DEL] Tunnel '%s' absent and kernel snapshot reconciled (remaining: %zu)",
                     tunnel_names[n], candidate.cfg.sdwan_tun_count);
        }
        reply_json(client_fd, 200,
                   already_absent == tunnel_count ?
                       "Tunnel already absent; stale kernel binding removed" :
                       "Tunnel deleted successfully");
    } else if (sync_result == KERNEL_SYNC_DEFERRED) {
        if (transaction_pending &&
            provision_transaction_update(
                &candidate, transaction_generation) != 0) {
            runtime_config_unlock();
            reply_json(client_fd, 409,
                       "Full apply transaction changed; retry delete");
            return;
        }
        runtime_config_unlock();
        log_warn("[DEL] Tunnel '%s' removed from pending full apply, but kernel cleanup is not applied yet",
                 tunnel_names[0]);
        reply_json(client_fd, 503,
                   "Tunnel cleanup pending; retry delete after kernel apply");
    } else {
        runtime_config_unlock();
        log_error("[DEL] Kernel cleanup not applied for tunnel '%s' (result=%d)",
                  tunnel_names[0], sync_result);
        reply_json(client_fd, 500, "Kernel tunnel cleanup was not applied");
    }
}

/* ---------- handle: del <profile_id> ------------------------------ */
static void handle_del_profile(int client_fd, int profile_id,
                               app_context_t *ctx)
{
    app_context_t candidate = {0};
    uint64_t previous_config_generation;
    uint64_t config_generation;

    if (provision_transaction_any()) {
        reply_json(client_fd, 409,
                   "Cannot delete profile while an apply/security transition is pending");
        return;
    }

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
    provision_reconcile_clear();
    cpu_tune_restore();
    clear_node_id();
    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: edit <profile_id> <fields...> ----------------- */
static void handle_edit_config_multi(int client_fd, int profile_id, const char *fields_str, app_context_t *ctx)
{
    app_context_t candidate = {0};
    app_context_t baseline = {0};
    app_context_t pending_candidate = {0};
    app_config_t refreshed = {0};
    enum provision_transaction_kind pending_kind = PROVISION_TX_NONE;
    uint64_t pending_generation = 0;
    uint64_t pending_previous_generation = 0;
    uint64_t previous_config_generation = 0;
    uint64_t config_generation = 0;

    log_info(">>> [EDIT] Profile %d: fields changed: '%s'", profile_id, fields_str);

    bool refresh_profiles = false;
    bool refresh_tunnels = false;
    bool refresh_pqc_keys = false;
    bool refresh_pqc_tunnels = false;
    bool refresh_pqc_binding = false;
    bool metadata_seen = false;
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
        if (config_edit_field_is_metadata(token)) {
            metadata_seen = true;
            token = strtok(NULL, " \t\r\n");
            continue;
        }
        if (strncmp(token, "sdwan_profiles.", 15) == 0) {
            refresh_profiles = true;
        } else if (strncmp(token, "sdwan_tunnels.", 14) == 0) {
            refresh_tunnels = true;
        } else if (strncmp(token, "pqc_keys.", 9) == 0) {
            refresh_pqc_keys = true;
        } else if (strncmp(token, "pqc_exchange_tunnels.", 21) == 0) {
            refresh_pqc_tunnels = true;
        } else if (strncmp(token, "sdwan_pqc_ref.", 14) == 0) {
            refresh_pqc_binding = true;
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
        snprintf(err_msg, sizeof(err_msg), "Unknown table prefix in '%s'. Use sdwan_profiles.<field>, sdwan_tunnels.<field>, pqc_keys.<field>, sdwan_pqc_ref.<field> or pqc_exchange_tunnels.<field>", unknown_name);
        reply_json(client_fd, 400, err_msg);
        return;
    }

    bool runtime_update_needed = false;
    bool sync_needed = false;
    bool weight_only_update = false;
    bool used_weight_update = false;
    bool failover_reconcile_needed = false;
    bool reload_pqc_lifecycle = false;
    bool trigger_pqc_handshake = false;
    bool stage_security_transition = false;
    bool replace_pending_full_apply = false;
    bool pqc_edit_requested = refresh_pqc_keys || refresh_pqc_tunnels ||
                              refresh_pqc_binding;

    if (provision_transaction_snapshot(profile_id, &pending_candidate,
                                       &pending_kind, &pending_generation,
                                       &pending_previous_generation)) {
        if (pending_kind != PROVISION_TX_FULL_APPLY || !pqc_edit_requested) {
            reply_json(client_fd, 409,
                       "Another apply/security transition is still pending");
            return;
        }
        replace_pending_full_apply = true;
    } else if (provision_transaction_any()) {
        reply_json(client_fd, 409,
                   "Another profile transition is still pending");
        return;
    }

    /* Profile weight_enable changes affect every tunnel's effective weight,
     * so profile and tunnel refreshes both reload one coherent snapshot. */
    if (refresh_profiles || refresh_tunnels) {
        if (db_client_load_config(profile_id, &refreshed) != 0) {
            reply_json(client_fd, 500, "Failed to reload profile config from DB");
            return;
        }
    }

    runtime_config_lock();
    candidate = replace_pending_full_apply ? pending_candidate : *ctx;
    baseline = candidate;

    if (refresh_profiles || refresh_tunnels) {

        /* Keep an already-derived PQC session key until the requested
         * handshake refresh below replaces it. The DB intentionally does
         * not contain this ephemeral traffic key. */
        if (baseline.cfg.encrypt.type == MWAN_CRYPT_PQC_GCM &&
            baseline.cfg.encrypt.key_len == PQC_TRAFFIC_KEY_SZ &&
            refreshed.encrypt.type == MWAN_CRYPT_PQC_GCM) {
            memcpy(refreshed.encrypt.key, baseline.cfg.encrypt.key,
                   PQC_TRAFFIC_KEY_SZ);
            refreshed.encrypt.key_len = PQC_TRAFFIC_KEY_SZ;
        }
        candidate.cfg = refreshed;
        runtime_update_needed = !config_runtime_equal(&baseline.cfg,
                                                      &candidate.cfg);
        sync_needed = !config_kernel_equal(&baseline.cfg, &candidate.cfg);
        weight_only_update = sync_needed &&
            config_kernel_weight_only_changed(&baseline.cfg,
                                              &candidate.cfg);
        failover_reconcile_needed = !config_failover_equal(
            &baseline.cfg, &candidate.cfg);
        if (runtime_update_needed)
            reload_pqc_lifecycle = config_pqc_policy_changed(
                &baseline.cfg, &candidate.cfg);
    }

    if (refresh_pqc_keys || refresh_pqc_tunnels || refresh_pqc_binding)
        reload_pqc_lifecycle = true;
    stage_security_transition = reload_pqc_lifecycle &&
        candidate.cfg.encrypt.enabled &&
        candidate.cfg.encrypt.type == MWAN_CRYPT_PQC_GCM;
    runtime_config_unlock();

    if (replace_pending_full_apply && !stage_security_transition) {
        reply_json(client_fd, 409,
                   "Pending PQC full apply cannot be replaced by a non-PQC edit");
        return;
    }

    if (!runtime_update_needed && !reload_pqc_lifecycle) {
        log_info("[EDIT] NOOP profile=%d metadata=%d; runtime datapath unchanged",
                 profile_id, metadata_seen ? 1 : 0);
        reply_json(client_fd, 200,
                   "Config updated; runtime datapath unchanged");
        return;
    }

    if (reload_pqc_lifecycle) {
        config_generation = runtime_config_begin_reload(
            &previous_config_generation);
        if (replace_pending_full_apply &&
            previous_config_generation != pending_generation) {
            runtime_config_cancel_reload(config_generation,
                                         previous_config_generation);
            reply_json(client_fd, 409,
                       "Full apply transaction changed; retry edit");
            return;
        }
    }

    runtime_config_lock();

    /* A PQC security edit is make-before-break.  The candidate must wait for
     * a newly authenticated traffic key; never copy the ACTIVE key into it. */
    if (stage_security_transition) {
        memset(candidate.cfg.encrypt.key, 0,
               sizeof(candidate.cfg.encrypt.key));
        candidate.cfg.encrypt.key_len = 0;
    }

    /* A PQC key callback may have completed between the DB read and this
     * commit. Preserve that newest runtime key in the candidate as well. */
    if (!stage_security_transition && sync_needed &&
        ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM &&
        ctx->cfg.encrypt.key_len == PQC_TRAFFIC_KEY_SZ &&
        candidate.cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        memcpy(candidate.cfg.encrypt.key, ctx->cfg.encrypt.key,
               PQC_TRAFFIC_KEY_SZ);
        candidate.cfg.encrypt.key_len = PQC_TRAFFIC_KEY_SZ;
    }

    // 3. Sync config to kernel if needed
    if (sync_needed && !stage_security_transition) {
        int sync_failed;

        used_weight_update = weight_only_update &&
            kernel_sync_current_config_generation() != 0;
        if (used_weight_update)
            sync_failed = kernel_sync_update_tunnel_weights(&candidate) != 0;
        else
            sync_failed = kernel_sync_push_config(&candidate) ==
                          KERNEL_SYNC_ERROR;
        if (sync_failed) {
            runtime_config_unlock();
            if (reload_pqc_lifecycle)
                runtime_config_cancel_reload(config_generation,
                                             previous_config_generation);
            reply_json(client_fd, 500, "Netlink push error");
            return;
        }
        *ctx = candidate;
        if (used_weight_update)
            log_info("[EDIT] Tunnel weights updated in place for profile %d; flow/BFD/worker state preserved",
                     profile_id);
        else {
            log_info("[EDIT] Profile/tunnel config refreshed for profile %d",
                     profile_id);
            log_info("[EDIT] Config changes successfully synced to kernel");
        }
    } else if (runtime_update_needed && !stage_security_transition) {
        /* Monitoring and other userspace-only values must be refreshed in
         * the active snapshot without replacing the kernel datapath. */
        *ctx = candidate;
        log_info("[EDIT] Userspace config refreshed for profile %d without kernel reload",
                 profile_id);
    }

    /* Weight, monitoring and other non-PQC profile changes must not disturb
     * an established PQC session. A new handshake is needed only when the
     * PQC lifecycle was deliberately reloaded above. */
    if (stage_security_transition)
        trigger_pqc_handshake = true;
    runtime_config_unlock();

    if (stage_security_transition) {
        if (replace_pending_full_apply) {
            if (provision_transaction_replace_full_apply(
                    &candidate, pending_generation, config_generation) != 0) {
                runtime_config_cancel_reload(config_generation,
                                             previous_config_generation);
                reply_json(client_fd, 409,
                           "Full apply transaction changed; retry edit");
                return;
            }
            provision_reconcile_accept(&candidate);
            log_info("[EDIT] Pending full apply replaced for profile %d generation=%llu old_generation=%llu base_generation=%llu",
                     profile_id, (unsigned long long)config_generation,
                     (unsigned long long)pending_generation,
                     (unsigned long long)pending_previous_generation);
        } else {
            provision_transaction_stage(PROVISION_TX_SECURITY_EDIT,
                                        &candidate, config_generation,
                                        previous_config_generation);
            log_info("[EDIT] Security candidate staged for profile %d; ACTIVE datapath/key remains in use",
                     profile_id);
        }
    }

    if (!stage_security_transition && failover_reconcile_needed &&
        (!sync_needed || used_weight_update)) {
        uint32_t kernel_generation =
            kernel_sync_current_config_generation();
        int failover_rc = failover_service_reconcile(&candidate,
                                                      kernel_generation);

        if (failover_rc != 0)
            log_warn("[EDIT] BFD reconcile deferred for profile %d: %s",
                     profile_id, strerror(-failover_rc));
    }

    if (replace_pending_full_apply ||
        (reload_pqc_lifecycle && !stage_security_transition)) {
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

    reply_json(client_fd, 200,
               replace_pending_full_apply ?
                   "Pending full apply updated; PQC handshake restarted" :
               stage_security_transition ?
                   "Security update accepted; old config remains active until handshake commit" :
                   "Config updated and synced successfully");
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

    /* get-peer-ip <data_tunnel_interface> */
    if (strncmp(buf, "get-peer-ip ", 12) == 0) {
        const char *ifname = buf + 12;
        size_t ifname_len = strnlen(ifname, IFNAMSIZ);

        if (ifname_len == 0 || ifname_len >= IFNAMSIZ ||
            ifname[ifname_len] != '\0' || strpbrk(ifname, " \t\r\n")) {
            reply_json(client_fd, 400,
                       "Usage: get-peer-ip <interface>");
            return;
        }
        handle_get_peer_ip(client_fd, ifname, running_ctx);
        return;
    }

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
