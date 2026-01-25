#ifndef AFPKT_H
#define AFPKT_H

#include "app_context.h"

int afpkt_open_rx(const char *ifname);
void afpkt_close(int fd);

int afpkt_poll_and_count(int fd);

int afpkt_poll_and_forward(int fd, const app_context_t *ctx);

#endif /* MWANC_USERIO_AFPKT_H */

