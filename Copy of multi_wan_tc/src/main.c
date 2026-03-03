#define _GNU_SOURCE
#include "app_context.h"
#include "system/system.h"
#include "tc/tc.h"
#include "utils/logger.h"
#include "userio/afpkt.h"
#include "proto/mwan_proto.h"
#include "proto/fragment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <features.h>

/* ---------- global state ---------- */

static volatile int running = 1;

/* ---------- thread affinity ---------- */

static int bind_thread_to_core(pthread_t thread, int core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    return pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}

/* ---------- signal handler ---------- */

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ---------- usage ---------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --config <file> --node <id> [--dump-config]\n", prog);
}

/* ---------- worker thread arg ---------- */

typedef struct
{
    afpkt_worker_t *worker;
    const afpkt_fanout_t *fg;
    app_context_t *ctx;
    volatile int *running;
    int is_outbound;
} worker_thread_arg_t;

static void *worker_fn(void *arg)
{
    worker_thread_arg_t *a = (worker_thread_arg_t *)arg;
    if (a->is_outbound)
        afpkt_worker_loop_outbound(a->worker, a->fg, a->ctx, a->running);
    else
        afpkt_worker_loop_inbound(a->worker, a->fg, a->ctx, a->running);
    return NULL;
}

static void *gc_worker_fn(void *arg)
{
    struct frag_table *ft = (struct frag_table *)arg;
    while (running) {
        frag_table_gc(ft);
        usleep(100000); /* 100ms */
    }
    return NULL;
}

/* ---------- helper: close single worker ---------- */

static void worker_close(afpkt_worker_t *w)
{
    if (w->ring)
    {
        munmap(w->ring, w->ring_size);
        w->ring = NULL;
    }
    if (w->tx_fd >= 0)
    {
        close(w->tx_fd);
        w->tx_fd = -1;
    }
    if (w->rx_fd >= 0)
    {
        close(w->rx_fd);
        w->rx_fd = -1;
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *node_id = NULL;
    int dump = 0;

    log_set_level(LOG_INFO);
    // log_set_level(LOG_DEBUG);

    /* ---- parse args ---- */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                usage(argv[0]);
                return 2;
            }
            config_path = argv[++i];
        }
        else if (strcmp(argv[i], "--node") == 0)
        {
            if (i + 1 >= argc)
            {
                usage(argv[0]);
                return 2;
            }
            node_id = argv[++i];
        }
        else if (strcmp(argv[i], "--dump-config") == 0)
        {
            dump = 1;
        }
        else if (strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            log_error("Unknown argument: %s", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!config_path || !node_id)
    {
        usage(argv[0]);
        return 2;
    }

    /* ---- load config ---- */
    app_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (app_context_init(&ctx, config_path, node_id) != 0)
    {
        log_error("Failed to load config");
        return 1;
    }

    if (dump)
        app_context_dump(&ctx);

    if (ctx.cfg.ne_tunnel_count == 0)
    {
        log_error("No ne_tunnel defined for node %s", node_id);
        return 1;
    }

    /* ---- STEP 1: enable ip_forward ---- */
    if (system_disable_ip_forward() != 0)
    {
        log_error("Failed to enable IP forwarding");
        return 1;
    }

    // /* ---- STEP 2: force routing into TC ---- */
    // if (system_add_route_dev(ctx.cfg.remote_cidr, ctx.cfg.local_if) != 0)
    // {
    //     log_error("Failed to add route for %s via %s",
    //               ctx.cfg.remote_cidr, ctx.cfg.local_if);
    //     return 1;
    // }

    /* ---- STEP 3: Disable offloads + Optimize Interfaces ---- */
    netdev_disable_offloads(ctx.cfg.local_if);
    netdev_optimize_interface(ctx.cfg.local_if);
    // for (size_t i = 0; i < ctx.cfg.wan_count; i++)
    //     netdev_optimize_interface(ctx.cfg.wans[i].ifname);

    /* ===================================================== */
    /* ==== PIPELINE: outbound on local_if ================= */
    /* ===================================================== */

    afpkt_pipeline_t pipeline;
    if (afpkt_pipeline_open(&pipeline, ctx.cfg.local_if, NUM_TX_WORKERS) != 0)
    {
        log_error("Failed to open pipeline on %s", ctx.cfg.local_if);
        goto cleanup_route;
    }

    /* Cache container (fanout struct used for tunnel/local cache only) */
    afpkt_fanout_t fg_out;
    memset(&fg_out, 0, sizeof(fg_out));

    struct frag_table *ft = malloc(sizeof(struct frag_table));
    if (ft) {
        frag_table_init(ft);
        fg_out.frag_tbl = ft;
    } else {
        log_error("Failed to allocate fragment table!");
        afpkt_pipeline_close(&pipeline);
        goto cleanup_route;
    }

    /* ===================================================== */
    /* ==== INBOUND: 1 single socket per ne_tunnel ========= */
    /* ===================================================== */

    afpkt_worker_t in_workers[MAX_NE_TUNNELS];
    size_t in_worker_count = 0;
    memset(in_workers, 0, sizeof(in_workers));
    for (size_t i = 0; i < MAX_NE_TUNNELS; i++)
    {
        in_workers[i].rx_fd = -1;
        in_workers[i].tx_fd = -1;
    }

    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++)
    {
        in_workers[w].id = (int)w;
        if (afpkt_single_open(&in_workers[w], ctx.cfg.ne_tunnels[w].ifname) != 0)
        {
            log_error("Failed to open inbound on %s", ctx.cfg.ne_tunnels[w].ifname);
            goto cleanup_inbound;
        }
        in_worker_count++;
    }

    /* ===================================================== */
    /* ==== INIT CACHES ==================================== */
    /* ===================================================== */

    afpkt_fanout_init_cache_outbound(&fg_out, &ctx);
    afpkt_fanout_init_cache_inbound(&fg_out, &ctx);

    /* ===================================================== */
    /* ==== START THREADS ================================== */
    /* ===================================================== */

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int available_cores[] = {1, 3, 5, 7, 9, 11};
    int num_available_cores = sizeof(available_cores) / sizeof(available_cores[0]);
    int current_core_idx = 0;

    /* ---- GC thread ---- */
    pthread_t gc_thread;
    if (pthread_create(&gc_thread, NULL, gc_worker_fn, fg_out.frag_tbl) != 0) {
        log_error("Failed to create GC thread");
        running = 0;
        goto cleanup_inbound;
    }
    int gc_core = available_cores[current_core_idx % num_available_cores];
    if (bind_thread_to_core(gc_thread, gc_core) == 0)
        log_info("Bound GC thread to core %d", gc_core);
    current_core_idx++;

    /* ---- Thread arrays ---- */
    /* Max threads: 1 RX + MAX_TX_WORKERS TX + MAX_NE_TUNNELS inbound */
    int max_threads = 1 + NUM_TX_WORKERS + (int)ctx.cfg.ne_tunnel_count;
    pthread_t *threads = calloc(max_threads, sizeof(pthread_t));
    int tidx = 0;

    /* ---- Pipeline RX thread arg ---- */
    typedef struct {
        afpkt_worker_t *rx;
        const afpkt_fanout_t *fg;
        struct pkt_queue **queues;
        int num_queues;
        volatile int *running;
    } rx_arg_t;

    rx_arg_t rx_arg = {
        .rx = &pipeline.rx,
        .fg = &fg_out,
        .queues = pipeline.queues,
        .num_queues = pipeline.num_tx_workers,
        .running = &running,
    };

    static void *rx_fn(void *a) {
        rx_arg_t *r = (rx_arg_t *)a;
        afpkt_rx_distribute_loop(r->rx, r->fg, r->queues, r->num_queues, r->running);
        return NULL;
    }

    if (pthread_create(&threads[tidx], NULL, rx_fn, &rx_arg) != 0) {
        log_error("Failed to create RX thread");
        running = 0;
        goto cleanup_inbound;
    }
    int rx_core = available_cores[current_core_idx % num_available_cores];
    if (bind_thread_to_core(threads[tidx], rx_core) == 0)
        log_info("Bound pipeline RX to core %d", rx_core);
    current_core_idx++;
    tidx++;

    /* ---- Pipeline TX worker thread args ---- */
    typedef struct {
        int id;
        struct pkt_queue *q;
        int tx_fd;
        const afpkt_fanout_t *fg;
        app_context_t *ctx;
        volatile int *running;
    } tx_arg_t;

    tx_arg_t tx_args[MAX_TX_WORKERS];

    static void *tx_fn(void *a) {
        tx_arg_t *t = (tx_arg_t *)a;
        afpkt_tx_worker_loop(t->id, t->q, t->tx_fd, t->fg, t->ctx, t->running);
        return NULL;
    }

    for (int i = 0; i < pipeline.num_tx_workers; i++) {
        tx_args[i] = (tx_arg_t){
            .id = i,
            .q = pipeline.queues[i],
            .tx_fd = pipeline.tx_fds[i],
            .fg = &fg_out,
            .ctx = &ctx,
            .running = &running,
        };
        if (pthread_create(&threads[tidx], NULL, tx_fn, &tx_args[i]) != 0) {
            log_error("Failed to create TX worker %d", i);
            running = 0;
            for (int k = 0; k < tidx; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_inbound;
        }
        int core_id = available_cores[current_core_idx % num_available_cores];
        if (bind_thread_to_core(threads[tidx], core_id) == 0)
            log_info("Bound pipeline TX worker %d to core %d", i, core_id);
        current_core_idx++;
        tidx++;
    }

    /* ---- Inbound workers (1 per ne_tunnel, unchanged) ---- */
    typedef struct {
        afpkt_worker_t *worker;
        const afpkt_fanout_t *fg;
        app_context_t *ctx;
        volatile int *running;
    } in_arg_t;

    in_arg_t in_args[MAX_NE_TUNNELS];

    static void *in_fn(void *a) {
        in_arg_t *ina = (in_arg_t *)a;
        afpkt_worker_loop_inbound(ina->worker, ina->fg, ina->ctx, ina->running);
        return NULL;
    }

    for (size_t w = 0; w < ctx.cfg.ne_tunnel_count; w++) {
        in_args[w] = (in_arg_t){
            .worker = &in_workers[w],
            .fg = &fg_out,
            .ctx = &ctx,
            .running = &running,
        };
        if (pthread_create(&threads[tidx], NULL, in_fn, &in_args[w]) != 0) {
            log_error("Failed to create inbound worker tunnel[%zu]", w);
            running = 0;
            for (int k = 0; k < tidx; k++)
                pthread_join(threads[k], NULL);
            goto cleanup_inbound;
        }
        int core_id = available_cores[current_core_idx % num_available_cores];
        if (bind_thread_to_core(threads[tidx], core_id) == 0)
            log_info("Bound inbound worker %zu to core %d", w, core_id);
        current_core_idx++;
        tidx++;
    }

    int total_threads = tidx;
    log_info("===========================================");
    log_info("  MWAN Pipeline Forwarding Started");
    log_info("  Mode: Pipeline (RX → Queue → TX Workers)");
    log_info("  Threads: 1 RX + %d TX + %d inbound + 1 GC = %d total",
             pipeline.num_tx_workers, (int)ctx.cfg.ne_tunnel_count,
             1 + pipeline.num_tx_workers + (int)ctx.cfg.ne_tunnel_count + 1);
    log_info("  OUTBOUND: %s → RX → %d queues → TX → TUNNEL[0..%zu]",
             ctx.cfg.local_if, pipeline.num_tx_workers,
             ctx.cfg.ne_tunnel_count - 1);
    log_info("  INBOUND:  TUNNEL[0..%zu] → %s",
             ctx.cfg.ne_tunnel_count - 1, ctx.cfg.local_if);
    log_info("  Press Ctrl+C to stop.");
    log_info("===========================================");

    /* Wait for all threads */
    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);

    pthread_join(gc_thread, NULL);
    free(threads);

    log_info("Cleaning up...");

    /* ---------- CLEANUP ---------- */

cleanup_inbound:
    for (size_t w = 0; w < in_worker_count; w++)
        worker_close(&in_workers[w]);

    if (fg_out.frag_tbl) {
        free(fg_out.frag_tbl);
        fg_out.frag_tbl = NULL;
    }

    afpkt_pipeline_close(&pipeline);

cleanup_route:
    system_restore_ip_forward();

    netdev_enable_offloads(ctx.cfg.local_if);
    netdev_reset_interface(ctx.cfg.local_if);

    log_info("Cleanup done.");
    return 0;
}
