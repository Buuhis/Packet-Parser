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
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  Forward declarations for functions defined in main.c              */
/* ------------------------------------------------------------------ */
extern void pqc_bind_node(int node_id);
extern void save_node_id(int node_id);

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

        /* ----- -a / --add <profile_id> <if_name> ---------------------------- */
        if ((strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--add") == 0) && i + 2 < argc) {
            int profile_id = atoi(argv[++i]);
            const char *if_name = argv[++i];
            if (profile_id <= 0) { fprintf(stderr, "Error: Invalid profile_id\n"); return 1; }
            char msg[128];
            snprintf(msg, sizeof(msg), "add %d %s", profile_id, if_name);
            return client_send_and_print(socket_path, msg);
        }

        /* ----- -d / --delete <profile_id> <if_name> ------------------------- */
        if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delete") == 0) && i + 2 < argc) {
            int profile_id = atoi(argv[++i]);
            const char *if_name = argv[++i];
            if (profile_id <= 0) { fprintf(stderr, "Error: Invalid profile_id\n"); return 1; }
            char msg[128];
            snprintf(msg, sizeof(msg), "del %d %s", profile_id, if_name);
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
    log_info(">>> Received configure request for Node ID: %d", req_id);

    app_config_t new_cfg;
    if (db_client_load_config(req_id, &new_cfg) != 0) {
        db_client_report_error(req_id, "Failed to load config from DB");
        reply_json(client_fd, 404, "Failed to load config from DB");
        return;
    }

    /* Resolve local network IP from interface name */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (strcmp(ifa->ifa_name, new_cfg.local_if) == 0) {
                new_cfg.local_ip   = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                new_cfg.local_mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
                new_cfg.local_ip  &= new_cfg.local_mask;
                struct in_addr a = { .s_addr = new_cfg.local_ip };
                log_info("[+] Auto-discovered Local Network: %s", inet_ntoa(a));
                break;
            }
        }
        freeifaddrs(ifaddr);
    }

    app_context_dump(&(app_context_t){new_cfg});
    ctx->cfg = new_cfg;

    if (kernel_sync_push_config(ctx) != 0) {
        log_error("Failed to push config to kernel");
        db_client_report_error(req_id, "Netlink push error");
        reply_json(client_fd, 500, "Netlink push error");
        return;
    }

    cpu_tune_apply(ctx);
    save_node_id(req_id);
    db_client_start_heartbeat(req_id);

    if (new_cfg.encrypt.enabled && new_cfg.encrypt.type == MWAN_CRYPT_PQC_GCM) {
        pqc_bind_node(req_id);
    }

    reply_json(client_fd, 200, "Success");
}

/* ---------- handle: add <profile_id> <if_name> -------------------- */
static void handle_add_tunnel(int client_fd, int profile_id, const char *if_name, app_context_t *ctx)
{
    log_info(">>> [ADD] Profile %d: adding tunnel '%s'", profile_id, if_name);

    if (ctx->cfg.sdwan_tun_count >= MAX_SDWAN_TUNS) {
        reply_json(client_fd, 400, "Maximum tunnel count reached");
        return;
    }

    /* Query this specific tunnel from DB */
    pthread_mutex_lock(&g_db_mutex);
    if (!g_db_conn) {
        pthread_mutex_unlock(&g_db_mutex);
        reply_json(client_fd, 500, "Database not connected");
        return;
    }

    char id_str[16], ifname_buf[16];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    snprintf(ifname_buf, sizeof(ifname_buf), "%s", if_name);
    const char *params[2] = { id_str, ifname_buf };

    PGresult *res = PQexecParams(g_db_conn,
        "SELECT i.interface, t.remote, t.weight, t.tunnel_port "
        "FROM public.sdwan_tunnels t "
        "JOIN public.interfaces i ON t.local = i.id "
        "WHERE t.profile_id = $1 AND i.interface = $2",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        log_error("[ADD] Tunnel '%s' not found in DB for profile %d", if_name, profile_id);
        if (res) PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        reply_json(client_fd, 404, "Tunnel not found in database");
        return;
    }

    /* Populate the new tunnel entry */
    size_t idx = ctx->cfg.sdwan_tun_count;
    memset(&ctx->cfg.sdwan_tuns[idx], 0, sizeof(sdwan_tun_cfg_t));
    strncpy(ctx->cfg.sdwan_tuns[idx].ifname,  PQgetvalue(res, 0, 0), sizeof(ctx->cfg.sdwan_tuns[idx].ifname) - 1);
    strncpy(ctx->cfg.sdwan_tuns[idx].gateway, PQgetvalue(res, 0, 1), sizeof(ctx->cfg.sdwan_tuns[idx].gateway) - 1);
    ctx->cfg.sdwan_tuns[idx].weight = atoi(PQgetvalue(res, 0, 2));
    ctx->cfg.sdwan_tuns[idx].port   = atoi(PQgetvalue(res, 0, 3));
    ctx->cfg.sdwan_tun_count++;

    PQclear(res);
    pthread_mutex_unlock(&g_db_mutex);

    /* Sync to kernel */
    if (kernel_sync_push_config(ctx) == 0) {
        log_info("[ADD] Tunnel '%s' added and synced to kernel (total: %zu)", if_name, ctx->cfg.sdwan_tun_count);
        reply_json(client_fd, 200, "Tunnel added successfully");
    } else {
        log_error("[ADD] Netlink push failed after adding tunnel '%s'", if_name);
        reply_json(client_fd, 500, "Netlink push error");
    }
}

/* ---------- handle: del <profile_id> <if_name> -------------------- */
static void handle_del_tunnel(int client_fd, int profile_id, const char *if_name, app_context_t *ctx)
{
    log_info(">>> [DEL] Profile %d: removing tunnel '%s'", profile_id, if_name);

    int found = -1;
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        if (strcmp(ctx->cfg.sdwan_tuns[i].ifname, if_name) == 0) {
            found = (int)i;
            break;
        }
    }

    if (found < 0) {
        log_warn("[DEL] Tunnel '%s' not found in running config", if_name);
        reply_json(client_fd, 404, "Tunnel not found in running config");
        return;
    }

    /* Shift remaining elements down */
    for (size_t i = (size_t)found; i < ctx->cfg.sdwan_tun_count - 1; i++) {
        ctx->cfg.sdwan_tuns[i] = ctx->cfg.sdwan_tuns[i + 1];
    }
    ctx->cfg.sdwan_tun_count--;
    memset(&ctx->cfg.sdwan_tuns[ctx->cfg.sdwan_tun_count], 0, sizeof(sdwan_tun_cfg_t));

    /* Sync to kernel */
    if (kernel_sync_push_config(ctx) == 0) {
        log_info("[DEL] Tunnel '%s' removed and synced to kernel (remaining: %zu)", if_name, ctx->cfg.sdwan_tun_count);
        reply_json(client_fd, 200, "Tunnel deleted successfully");
    } else {
        log_error("[DEL] Netlink push failed after removing tunnel '%s'", if_name);
        reply_json(client_fd, 500, "Netlink push error");
    }
}

/* ---------- handle: edit <profile_id> <fields...> ----------------- */
static void handle_edit_config_multi(int client_fd, int profile_id, const char *fields_str, app_context_t *ctx)
{
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
        if (strncmp(token, "sdwan_profiles.", 15) == 0 || strncmp(token, "nodes.", 6) == 0) {
            refresh_profiles = true;
        } else if (strncmp(token, "sdwan_tunnels.", 14) == 0 || strncmp(token, "sdwan_tuns.", 11) == 0) {
            refresh_tunnels = true;
        } else if (strncmp(token, "pqc_keys.", 9) == 0 || strncmp(token, "pqc_identities.", 15) == 0) {
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

    // 1. Refresh sdwan_profiles if needed
    if (refresh_profiles) {
        app_config_t refreshed;
        if (db_client_load_config(profile_id, &refreshed) != 0) {
            reply_json(client_fd, 500, "Failed to reload sdwan_profiles config from DB");
            return;
        }
        ctx->cfg.encrypt = refreshed.encrypt;
        log_info("[EDIT] Encryption/Profile config refreshed from DB for profile %d", profile_id);
        sync_needed = true;
    }

    // 2. Refresh sdwan_tunnels if needed
    if (refresh_tunnels) {
        pthread_mutex_lock(&g_db_mutex);
        if (!g_db_conn) {
            pthread_mutex_unlock(&g_db_mutex);
            reply_json(client_fd, 500, "Database not connected");
            return;
        }

        char id_str[16];
        snprintf(id_str, sizeof(id_str), "%d", profile_id);
        const char *params[1] = { id_str };

        PGresult *res = PQexecParams(g_db_conn,
            "SELECT i.interface, t.remote, t.weight, t.tunnel_port "
            "FROM public.sdwan_tunnels t "
            "JOIN public.interfaces i ON t.local = i.id "
            "WHERE t.profile_id = $1 ORDER BY t.id",
            1, NULL, params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            log_error("[EDIT] Failed to re-query sdwan_tunnels: %s", PQerrorMessage(g_db_conn));
            PQclear(res);
            pthread_mutex_unlock(&g_db_mutex);
            reply_json(client_fd, 500, "Failed to reload tunnel config from DB");
            return;
        }

        int num = PQntuples(res);
        ctx->cfg.sdwan_tun_count = (num < MAX_SDWAN_TUNS) ? (size_t)num : MAX_SDWAN_TUNS;

        for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
            memset(&ctx->cfg.sdwan_tuns[i], 0, sizeof(sdwan_tun_cfg_t));
            strncpy(ctx->cfg.sdwan_tuns[i].ifname,  PQgetvalue(res, (int)i, 0), sizeof(ctx->cfg.sdwan_tuns[i].ifname) - 1);
            strncpy(ctx->cfg.sdwan_tuns[i].gateway, PQgetvalue(res, (int)i, 1), sizeof(ctx->cfg.sdwan_tuns[i].gateway) - 1);
            ctx->cfg.sdwan_tuns[i].weight = atoi(PQgetvalue(res, (int)i, 2));
            ctx->cfg.sdwan_tuns[i].port   = atoi(PQgetvalue(res, (int)i, 3));
        }

        PQclear(res);
        pthread_mutex_unlock(&g_db_mutex);
        log_info("[EDIT] Tunnel config refreshed from DB for profile %d", profile_id);
        sync_needed = true;
    }

    // 3. Sync config to kernel if needed
    if (sync_needed) {
        if (kernel_sync_push_config(ctx) != 0) {
            reply_json(client_fd, 500, "Netlink push error");
            return;
        }
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

    /* add <profile_id> <if_name> */
    if (strncmp(buf, "add ", 4) == 0) {
        int pid = 0;
        char ifn[64] = {0};
        if (sscanf(buf + 4, "%d %63s", &pid, ifn) == 2 && pid > 0) {
            handle_add_tunnel(client_fd, pid, ifn, running_ctx);
        } else {
            reply_json(client_fd, 400, "Usage: add <profile_id> <if_name>");
        }
        return;
    }

    /* del <profile_id> <if_name> */
    if (strncmp(buf, "del ", 4) == 0) {
        int pid = 0;
        char ifn[64] = {0};
        if (sscanf(buf + 4, "%d %63s", &pid, ifn) == 2 && pid > 0) {
            handle_del_tunnel(client_fd, pid, ifn, running_ctx);
        } else {
            reply_json(client_fd, 400, "Usage: del <profile_id> <if_name>");
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
