#ifndef AFPKT_H
#define AFPKT_H

#include "app_context.h"
#include <stddef.h>

typedef struct {
    int fd;
    void *ring;
    size_t frame_nr;
    size_t frame_size;
    size_t frame_idx;
} afpkt_rx_ctx_t;

int afpkt_open_rx(const char *ifname);
void afpkt_close(int fd);

int afpkt_poll_and_count(int fd);

int afpkt_poll_and_forward(int fd, const app_context_t *ctx);

// ===========================================

int afpkt_rx_open(afpkt_rx_ctx_t *rx, const char *ifname,
                  size_t frame_nr, size_t frame_size);

void afpkt_rx_close(afpkt_rx_ctx_t *rx);

/* poll + count packets; returns number of forwarded/handled packets in this poll */
int afpkt_rx_poll_count(afpkt_rx_ctx_t *rx);

/* RX-3 & RX-4: rewrite MAC then send out local_if */
int afpkt_rx_poll_forward_local(afpkt_rx_ctx_t *rx,
                                int tx_fd,
                                unsigned int local_ifindex,
                                const unsigned char local_src_mac[6],
                                const unsigned char lan_dst_mac[6]);

#endif /* MWANC_USERIO_AFPKT_H */

