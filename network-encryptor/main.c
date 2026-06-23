#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"
#include "db_config.h"
#include "db_env.h"
#include "db_runtime.h"
#include "forwarder.h"
#include "main_diag.h"
#include "sig_encrypt/inc/traffic_crypto.h"
#include "sig_encrypt/inc/pqc_handshake.h"
#include "sig_encrypt/inc/pqc_ipc.h"
#include "cfm_diag.h"

#define NOTIFY_CHANNEL "xdp_start"

struct runtime_state {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg_slots[2];
    int active_slot;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon mode (LISTEN %s)\n"
            "  %s -gi            # generate new identity key and load into RAM\n"
            "  %s -check-identity # check PQC DB identity integrity and link to RAM cache\n"
            "  %s -id <ID>       # notify daemon to apply config already stored in DB\n"
            "  %s -check [ID]    # check database config consistency\n"
            "  %s -r <policy_id> # trigger manual handshake retry for policy\n",
            prog, NOTIFY_CHANNEL, prog, prog, prog, prog, prog);
}

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static void *forwarder_thread_main(void *arg) {
    struct runtime_state *rt = (struct runtime_state *)arg;
    if (forwarder_init(&rt->fwd, &rt->cfg_slots[rt->active_slot]) != 0) {
        fprintf(stderr, "[FATAL] forwarder_init failed for merged active configs\n");
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    forwarder_cleanup(&rt->fwd);
    rt->running = 0;
    return NULL;
}

static int runtime_start(struct runtime_state *rt, const struct app_config *cfg) {
    rt->active_slot = 0;
    rt->cfg_slots[rt->active_slot] = *cfg;
    rt->running = 0;
    
    // Initialize L2 CFM diagnostics before starting forwarder thread
    cfm_init(cfg);

    if (pthread_create(&rt->thread, NULL, forwarder_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        cfm_cleanup();
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

static void handle_shutdown_signal(int sig) {
    (void)sig;
    sig_pqc_cleanup_ipc();
    cfm_cleanup();
    exit(0);
}

int main(int argc, char **argv) {
    int ipc_rc = sig_pqc_handle_ipc_cli(argc, argv);
    if (ipc_rc >= 0) {
        return ipc_rc;
    }

    load_env_from_file("/opt/db_test.env");
    const char *db_pass = resolve_db_password();
    const char *keywords[] = {"host", "port", "dbname", "user", "password", "connect_timeout", NULL};
    const char *values[]   = {getenv("POSTGRES_HOST"), getenv("POSTGRES_PORT"), getenv("POSTGRES_TABLE"),
                              getenv("POSTGRES_USER"), db_pass, "10", NULL};


    if (argc > 1 && strcmp(argv[1], "-gi") == 0) {
        sig_pqc_handle_gen_identity();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "-check-identity") == 0) {
        if (db_check_identities(NULL) == 0) {
            printf("[PQC-CHECK] Completed successfully.\n");
        } else {
            fprintf(stderr, "[PQC-CHECK] ERROR: Failed to run check.\n");
        }
        return 0;
    }

    int config_id = -1;
    int check_mode = 0;
    int check_id = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            if (parse_config_id_arg(argv[++i], &config_id) != 0) {
                fprintf(stderr, "[FATAL] config_id must be a number (digits only)\n");
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-check") == 0) {
            check_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (parse_config_id_arg(argv[++i], &check_id) != 0) {
                    fprintf(stderr, "[FATAL] check id must be a number (digits only)\n");
                    usage(argv[0]);
                    return 1;
                }
            }
        }
    }

    if (check_mode) {
        if (!db_pass || !*db_pass) {
            fprintf(stderr,
                    "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or provide /opt/db.env).\n");
            return 1;
        }
        return run_db_check(keywords, values, check_id);
    }

    if (config_id >= 0) {
        if (!db_pass || !*db_pass) {
            fprintf(stderr,
                    "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or provide /opt/db.env).\n");
            return 1;
        }

        PGconn *conn = PQconnectdbParams(keywords, values, 0);
        if (PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(conn));
            PQfinish(conn);
            return 1;
        }

        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d", config_id);
        const char *check_params[1] = { id_str };
        PGresult *check_res = PQexecParams(
            conn,
            "SELECT 1 FROM xdp_configs WHERE id = $1::int",
            1,
            NULL,
            check_params,
            NULL,
            NULL,
            0);
        if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "[FATAL] config id lookup failed: %s", PQerrorMessage(conn));
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }
        if (PQntuples(check_res) == 0) {
            fprintf(stderr, "[FATAL] config_id=%d not found in xdp_configs (backend must insert it first)\n",
                    config_id);
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }
        PQclear(check_res);

        const char *notifyParams[2] = { NOTIFY_CHANNEL, id_str };
        PGresult *notify_res = PQexecParams(
            conn,
            "SELECT pg_notify($1, $2);",
            2,
            NULL,
            notifyParams,
            NULL,
            NULL,
            0);
        ExecStatusType st = PQresultStatus(notify_res);
        if (!(st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK)) {
            fprintf(stderr, "[FATAL] pg_notify failed: %s", PQerrorMessage(conn));
            if (notify_res) PQclear(notify_res);
            PQfinish(conn);
            return 1;
        }
        if (notify_res) PQclear(notify_res);
        PQfinish(conn);

        fprintf(stderr, "[OK] Notified %s with config_id=%d\n", NOTIFY_CHANNEL, config_id);
        return 0;
    }

    if (!db_pass || !*db_pass) {
        fprintf(stderr,
                "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or /opt/db.env)\n");
        return 1;
    }
    
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[FATAL] Failed to initialize PQC subsystem.\n");
        return 1;
    }

    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);

    sig_pqc_start_ipc_server();

    libbpf_set_print(libbpf_print_silent);
    PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    struct runtime_state rt;
    memset(&rt, 0, sizeof(rt));
    int active_ids[32];
    int active_id_count = 0;

    for (;;) {
        int pq_fd = PQsocket(listen_conn);
        if (pq_fd < 0) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
            usleep(200000);
            continue;
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0)
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = atoi(notify->extra);
            int exists = 0;
            for (int i = 0; i < active_id_count; i++) {
                if (active_ids[i] == id) {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                if (active_id_count >= (int)(sizeof(active_ids) / sizeof(active_ids[0]))) {
                    fprintf(stderr, "[WARN] active config set is full, ignoring id=%d\n", id);
                    PQfreemem(notify);
                    continue;
                }
                active_ids[active_id_count++] = id;
            }

            struct app_config merged_cfg;
            if (build_merged_config(&merged_cfg, active_ids, active_id_count, db_pass) == 0) {
                main_diag_log_loaded_config(&merged_cfg, id);
                if (!rt.has_thread) {
                    if (runtime_start(&rt, &merged_cfg) != 0) {
                        fprintf(stderr, "[FATAL] failed to start merged runtime\n");
                    } else {
                        fprintf(stderr, "[OK] Applied merged runtime with %d active config(s)\n", active_id_count);
                    }
                } else {
                    int next_slot = 1 - rt.active_slot;
                    rt.cfg_slots[next_slot] = merged_cfg;
                    if (forwarder_reload_config(&rt.fwd, &rt.cfg_slots[next_slot]) == 0) {
                        rt.active_slot = next_slot;
                        
                        // Hot-reload L2 CFM diagnostics with updated WAN configurations
                        cfm_init(&rt.cfg_slots[rt.active_slot]);

                        fprintf(stderr, "[OK] Hot-reloaded merged runtime with %d active config(s)\n", active_id_count);
                    } else {
                        fprintf(stderr,
                                "[WARN] hot reload rejected for safety; keep current runtime unchanged "
                                "(prevents traffic interruption)\n");
                    }
                }
            } else {
                fprintf(stderr, "[FATAL] failed to build merged config set after notify id=%d\n", id);
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }
}