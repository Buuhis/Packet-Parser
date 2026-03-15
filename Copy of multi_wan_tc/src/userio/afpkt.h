#ifndef AFPKT_H
#define AFPKT_H

#include "app_context.h"
#include "proto/mwan_proto.h"
#include "proto/fragment.h"

#include <netinet/in.h>

#define MAX_FANOUT_WORKERS 6
#define NUM_TX_WORKERS 3  /* default, adjustable */

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
    afpkt_worker_t   workers[MAX_FANOUT_WORKERS];

    /* Cached MAC/ifindex for WAN interfaces (legacy, kept for reference) */
    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } wans[MAX_WANS];

    /* Cached UDP socket + sockaddr_in per tunnel for VXLAN outbound TX */
    int tunnel_udp_fds[MAX_NE_TUNNELS];
    struct sockaddr_in tunnel_addrs[MAX_NE_TUNNELS];
    size_t tunnel_count;

    struct {
        int ifindex;
        unsigned char src_mac[6];
        int valid;
    } local;

    struct frag_table *frag_tbl;
} afpkt_fanout_t;

/* ============ Fanout API ============ */

int  afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id, int num_workers);
int  afpkt_single_open(afpkt_worker_t *w, const char *ifname);
void afpkt_fanout_close(afpkt_fanout_t *fg);

void afpkt_fanout_init_cache_outbound(afpkt_fanout_t *fg, const app_context_t *ctx);
void afpkt_fanout_init_cache_inbound(afpkt_fanout_t *fg, const app_context_t *ctx);

/* Outbound: capture from local_if → VXLAN encapsulate → send via UDP */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                 const app_context_t *ctx, volatile int *running);

/* Inbound: receive VXLAN from UDP → strip → reassemble → forward to LAN */
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, const char *listen_ifname, volatile int *running);

#endif /* AFPKT_H */
