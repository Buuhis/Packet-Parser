#define _GNU_SOURCE
#include "dataplane.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"
#include "proto/mwan_proto.h"
#include "proto/fragment.h"
#include "system/arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <net/if.h>

/* ---------- internal state ---------- */
static volatile int running_dataplane = 0;
static afpkt_fanout_t fg_out;
static afpkt_worker_t in_workers[MAX_NE_TUNNELS];
static size_t in_worker_count = 0;
static int total_worker_threads = 0;
static pthread_t maintenance_thread;
static pthread_t *worker_threads = NULL;
static app_context_t running_ctx;
static int is_dataplane_active = 0;

/* ---- Internal structures for thread args ---- */
typedef struct {
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
} out_arg_t;

typedef struct {
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    char           listen_ifname[IF_NAMESIZE];
    volatile int *running;
} in_arg_t;

static out_arg_t g_out_args[MAX_FANOUT_WORKERS];
static in_arg_t g_in_args[MAX_NE_TUNNELS];

/* ---------- thread affinity ---------- */
static int bind_thread_to_core(pthread_t thread, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    return pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}

static inline int get_next_odd_core(int *current_idx, int max_cores) {
    if (max_cores <= 1) return 0;
    int core = *current_idx;
    if (core % 2 == 0) core++; 
    if (core >= max_cores) core = 1;
    *current_idx = core + 2;
    return core;
}

/* ---------- worker functions ---------- */
static void *out_fn(void *a) {
    out_arg_t *o = (out_arg_t *)a;
    afpkt_worker_loop_outbound(o->worker, o->fg, o->ctx, o->running);
    return NULL;
}

static void *in_fn(void *a) {
    in_arg_t *ina = (in_arg_t *)a;
    afpkt_worker_loop_inbound(ina->worker, ina->fg, ina->ctx, ina->listen_ifname, ina->running);
    return NULL;
}

static void *maintenance_worker_fn(void *arg) {
    afpkt_fanout_t *fg = (afpkt_fanout_t *)arg;
    int heartbeat_cnt = 0;

    log_info("Maintenance thread started (GC + Health Check)");
    while (running_dataplane) {
        /* 1. Fragment GC (every 100ms) */
        if (fg->frag_tbl) {
            frag_table_gc(fg->frag_tbl);
        }

        /* 2. Heartbeat & Health Check (every 1s) */
        if (++heartbeat_cnt >= 10) {
            afpkt_fanout_send_heartbeats(fg);
            afpkt_fanout_check_health(fg);
            heartbeat_cnt = 0;
        }

        usleep(100000); /* 100ms interval */
    }
    return NULL;
}

/* ---------- public API ---------- */

int dataplane_is_active(void) {
    return is_dataplane_active;
}

void dataplane_stop(void) {
    if (!is_dataplane_active) return;
    
    log_info("Stopping Dataplane...");
    running_dataplane = 0;
    
    if (worker_threads) {
        for (int i = 0; i < total_worker_threads; i++) {
            pthread_join(worker_threads[i], NULL);
        }
        free(worker_threads);
        worker_threads = NULL;
    }
    pthread_join(maintenance_thread, NULL);
    
    if (fg_out.frag_tbl) {
        free(fg_out.frag_tbl);
        fg_out.frag_tbl = NULL;
    }
    
    afpkt_fanout_close(&fg_out);

    for (size_t i = 0; i < in_worker_count; i++) {
        if (in_workers[i].ring) {
            munmap(in_workers[i].ring, in_workers[i].ring_size);
            in_workers[i].ring = NULL;
        }
        if (in_workers[i].rx_fd >= 0) close(in_workers[i].rx_fd);
        if (in_workers[i].tx_fd >= 0) close(in_workers[i].tx_fd);
    }
    in_worker_count = 0;
    
    tc_ingress_cleanup(running_ctx.cfg.local_if);
    for (size_t i = 0; i < running_ctx.cfg.ne_tunnel_count; i++) {
        tc_ingress_cleanup(running_ctx.cfg.ne_tunnels[i].ifname);
    }
    
    netdev_enable_offloads(running_ctx.cfg.local_if);
    netdev_reset_interface(running_ctx.cfg.local_if);
    
    /* ---- STEP X: Cleanup Loopback IP ---- */
    netdev_del_loopback_ip(running_ctx.cfg.loopback_ip);
    
    is_dataplane_active = 0;
    total_worker_threads = 0;
    log_info("Dataplane stopped cleanly.");
}

int dataplane_start(app_context_t *ctx) {
    if (is_dataplane_active) {
        dataplane_stop();
    }
    
    log_info("Starting Dataplane for Node ID: %d", ctx->cfg.node_id);
    running_ctx = *ctx;
    running_dataplane = 1;

    /* ---- STEP 0: Loopback IP ---- */
    netdev_add_loopback_ip(ctx->cfg.loopback_ip);

    /* ---- STEP 1: TC Ingress Drop ---- */
    if (tc_ingress_drop_cidr(ctx->cfg.local_if, ctx->cfg.remote_cidr) != 0) {
        log_error("Failed to add TC ingress drop on %s", ctx->cfg.local_if);
    }
    
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        tc_ingress_drop_cidr(ctx->cfg.ne_tunnels[i].ifname, "0.0.0.0/0");
    }

    /* ---- STEP 2: Interface Optimizations ---- */
    netdev_disable_offloads(ctx->cfg.local_if);
    netdev_optimize_interface(ctx->cfg.local_if);

    /* ---- STEP 2.5: ARP Cache and Scanning ---- */
    uint32_t local_ip, local_mask;
    unsigned char local_mac[6];
    if (system_get_if_hwaddr(ctx->cfg.local_if, local_mac) == 0 &&
        system_get_if_ip_and_mask(ctx->cfg.local_if, &local_ip, &local_mask) == 0) {
        arp_cache_init();
        arp_scanner_scan_subnet(ctx->cfg.local_if, local_ip, local_mask, local_mac);
    } else {
        log_warn("Dataplane: Failed to get IP/MAC for %s, skipping ARP scan", ctx->cfg.local_if);
    }

    /* ---- STEP 3: Fanout & Inbound Workers ---- */
    if (afpkt_fanout_open(&fg_out, ctx->cfg.local_if, 1, NUM_TX_WORKERS) != 0) {
        log_error("Failed to open fanout outbound on %s", ctx->cfg.local_if);
        goto cleanup_route;
    }

    struct frag_table *ft = malloc(sizeof(struct frag_table));
    if (ft) {
        frag_table_init(ft);
        fg_out.frag_tbl = ft;
    } else {
        log_error("Failed to allocate fragment table!");
        goto cleanup_pl_out;
    }

    in_worker_count = 0;
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count && i < MAX_NE_TUNNELS; i++) {
        const char *tnl_if = ctx->cfg.ne_tunnels[i].ifname;
        if (afpkt_single_open_inbound(&in_workers[in_worker_count], tnl_if, (int)i) == 0) {
            in_worker_count++;
        } else {
            log_error("Failed to open inbound worker for tunnel %s", tnl_if);
        }
    }

    afpkt_fanout_init_cache_outbound(&fg_out, ctx);
    afpkt_fanout_init_cache_inbound(&fg_out, ctx);

    int num_available_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_available_cores <= 0) num_available_cores = 1;
    int current_core_idx = 1;

    if (pthread_create(&maintenance_thread, NULL, maintenance_worker_fn, &fg_out) != 0) {
        log_error("Failed to create Maintenance thread");
        goto cleanup_pl_out;
    }
    bind_thread_to_core(maintenance_thread, get_next_odd_core(&current_core_idx, num_available_cores));

    int max_threads = fg_out.num_workers + (int)in_worker_count;
    worker_threads = calloc(max_threads, sizeof(pthread_t));
    total_worker_threads = 0;

    for (int i = 0; i < fg_out.num_workers; i++) {
        g_out_args[i] = (out_arg_t){
            .worker = &fg_out.workers[i], .fg = &fg_out, .ctx = ctx, .running = &running_dataplane,
        };
        pthread_create(&worker_threads[total_worker_threads], NULL, out_fn, &g_out_args[i]);
        bind_thread_to_core(worker_threads[total_worker_threads], get_next_odd_core(&current_core_idx, num_available_cores));
        total_worker_threads++;
    }

    for (size_t i = 0; i < in_worker_count; i++) {
        g_in_args[i] = (in_arg_t){
            .worker = &in_workers[i], .fg = &fg_out, .ctx = ctx, .running = &running_dataplane,
        };
        pthread_create(&worker_threads[total_worker_threads], NULL, in_fn, &g_in_args[i]);
        bind_thread_to_core(worker_threads[total_worker_threads], get_next_odd_core(&current_core_idx, num_available_cores));
        total_worker_threads++;
    }

    log_info("Dataplane Started. Node ID: %d", ctx->cfg.node_id);
    is_dataplane_active = 1;
    return 0;

cleanup_pl_out:
    if (fg_out.frag_tbl) { free(fg_out.frag_tbl); fg_out.frag_tbl = NULL; }
    afpkt_fanout_close(&fg_out);
cleanup_route:
    tc_ingress_cleanup(ctx->cfg.local_if);
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) tc_ingress_cleanup(ctx->cfg.ne_tunnels[i].ifname);
    netdev_enable_offloads(ctx->cfg.local_if);
    netdev_reset_interface(ctx->cfg.local_if);
    is_dataplane_active = 0;
    return -1;
}
