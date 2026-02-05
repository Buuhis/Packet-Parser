#ifndef AFPKT_H
#define AFPKT_H

#include "app_context.h"

#define NUM_WORKERS 10

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

/* Fanout group containing N workers */
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

    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } local;
} afpkt_fanout_t;

/* Open N sockets on ifname, join fanout group */
int  afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id);
void afpkt_fanout_close(afpkt_fanout_t *fg);

/* Init cache (call once before starting threads) */
void afpkt_fanout_init_cache_outbound(afpkt_fanout_t *fg, const app_context_t *ctx);
void afpkt_fanout_init_cache_inbound(afpkt_fanout_t *fg, const app_context_t *ctx);

/* Worker loops — each thread runs one of these */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                 const app_context_t *ctx, volatile int *running);
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running);

#endif /* AFPKT_H */
