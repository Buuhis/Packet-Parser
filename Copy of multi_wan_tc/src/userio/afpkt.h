#ifndef AFPKT_H
#define AFPKT_H

#include "app_context.h"
#include "proto/mwan_proto.h"
#include "proto/fragment.h"
#include "userio/pkt_queue.h"

#define NUM_WORKERS 2

/* Each worker owns 1 RX socket (fanout) + 1 TX socket */
typedef struct {
    int             id;
    int             rx_fd;
    int             tx_fd;
    void           *ring;
    size_t          ring_size;

    /* TPACKET_V3 specific state */
    unsigned int    block_count;   /* Number of blocks in ring (req.tp_block_nr) */
    unsigned int    current_block; /* Index of current block being processed */
} afpkt_worker_t;

/* Fanout group — used as cache container for tunnel/local info */
typedef struct {
    int              num_workers;
    int              fanout_group_id;
    afpkt_worker_t   workers[NUM_WORKERS];

    /* Cached MAC/ifindex (written once before threads start, read-only after) */
    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } wans[MAX_WANS];

    /* Cached ne_tunnel MAC/ifindex for outbound TX */
    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } tunnels[MAX_NE_TUNNELS];

    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } local;

    struct frag_table *frag_tbl;
} afpkt_fanout_t;

/* ============ Pipeline architecture ============ */

#define MAX_TX_WORKERS 8
#define NUM_TX_WORKERS 2  /* default, adjustable */

typedef struct {
    /* RX: single TPACKET_V3 socket on local_if (no fanout) */
    afpkt_worker_t rx;

    /* Per-TX-worker packet queue (heap-allocated) */
    struct pkt_queue *queues[MAX_TX_WORKERS];

    /* Per-TX-worker raw TX socket */
    int tx_fds[MAX_TX_WORKERS];

    int num_tx_workers;
} afpkt_pipeline_t;

/* ============ Fanout API (legacy, still used for inbound) ============ */

int  afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id);
int  afpkt_single_open(afpkt_worker_t *w, const char *ifname);
void afpkt_fanout_close(afpkt_fanout_t *fg);

void afpkt_fanout_init_cache_outbound(afpkt_fanout_t *fg, const app_context_t *ctx);
void afpkt_fanout_init_cache_inbound(afpkt_fanout_t *fg, const app_context_t *ctx);

/* Legacy outbound (single-thread per worker, used before pipeline) */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                 const app_context_t *ctx, volatile int *running);
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running);

/* ============ Pipeline API ============ */

int  afpkt_pipeline_open(afpkt_pipeline_t *pl, const char *ifname, int num_tx_workers);
void afpkt_pipeline_close(afpkt_pipeline_t *pl);

/* RX thread: read from ring → filter → push to TX worker queues (round-robin) */
void afpkt_rx_distribute_loop(afpkt_worker_t *rx_w,
                               const afpkt_fanout_t *fg,
                               struct pkt_queue **queues, int num_queues,
                               volatile int *running);

/* TX worker: dequeue → fragment → ETH rewrite → sendmmsg to tunnel */
void afpkt_tx_worker_loop(int worker_id, struct pkt_queue *q, int tx_fd,
                           const afpkt_fanout_t *fg,
                           const app_context_t *ctx,
                           volatile int *running);

#endif /* AFPKT_H */
