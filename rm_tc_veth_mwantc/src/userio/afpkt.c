#define _GNU_SOURCE
#include "userio/afpkt.h"
#include "utils/logger.h"
#include "system/system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

/* ---- tuning constants ---- */
#define RX_BLOCK_SIZE   (1 << 20)   /* 1MB */
#define RX_FRAME_SIZE   2048
#define RX_BLOCK_NR     64

/* ================================================== */
/* ============ FANOUT OPEN / CLOSE ================= */
/* ================================================== */

int afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id)
{
    memset(fg, 0, sizeof(*fg));
    fg->num_workers = NUM_WORKERS;
    fg->fanout_group_id = fanout_group_id;

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        afpkt_worker_t *w = &fg->workers[i];
        w->id = i;

        /* 1. RX socket */
        w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->rx_fd < 0) {
            log_error("Fanout[%d] worker %d: socket(RX) failed: %s",
                      fanout_group_id, i, strerror(errno));
            return -1;
        }

        /* 2. Ignore outgoing packets (only capture RX) */
        /*    Prevents loop: inbound worker sendto(eth0) → outbound captures it again */
        int ignore_out = 1;
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                       &ignore_out, sizeof(ignore_out)) != 0) {
            log_error("Fanout[%d] worker %d: PACKET_IGNORE_OUTGOING failed: %s "
                      "(kernel >= 5.15 required)",
                      fanout_group_id, i, strerror(errno));
        }

        /* 3. Bind to interface */
        struct sockaddr_ll sll = {
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex  = ifidx,
        };
        if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            log_error("Fanout[%d] worker %d: bind(%s) failed: %s",
                      fanout_group_id, i, ifname, strerror(errno));
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        /* 4. RX ring (each worker gets its own ring) */
        struct tpacket_req req;
        memset(&req, 0, sizeof(req));
        req.tp_block_size = RX_BLOCK_SIZE;
        req.tp_frame_size = RX_FRAME_SIZE;
        req.tp_block_nr   = RX_BLOCK_NR;
        req.tp_frame_nr   = ((unsigned long)RX_BLOCK_SIZE * RX_BLOCK_NR) / RX_FRAME_SIZE;

        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING,
                       &req, sizeof(req)) != 0) {
            log_error("Fanout[%d] worker %d: PACKET_RX_RING failed: %s",
                      fanout_group_id, i, strerror(errno));
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        size_t ring_sz = (size_t)req.tp_block_size * req.tp_block_nr;
        w->ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED, w->rx_fd, 0);
        if (w->ring == MAP_FAILED) {
            log_error("Fanout[%d] worker %d: mmap failed: %s",
                      fanout_group_id, i, strerror(errno));
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }
        w->ring_size = ring_sz;
        w->frame_nr  = req.tp_frame_nr;
        w->frame_idx = 0;

        /* 5. PACKET_FANOUT — kernel distributes packets by 5-tuple hash */
        int fanout_arg = (fanout_group_id & 0xFFFF)
                       | (PACKET_FANOUT_HASH << 16);
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_FANOUT,
                       &fanout_arg, sizeof(fanout_arg)) != 0) {
            log_error("Fanout[%d] worker %d: PACKET_FANOUT failed: %s",
                      fanout_group_id, i, strerror(errno));
            munmap(w->ring, w->ring_size);
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        /* 6. TX socket (each worker gets its own) */
        w->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->tx_fd < 0) {
            log_error("Fanout[%d] worker %d: socket(TX) failed: %s",
                      fanout_group_id, i, strerror(errno));
            munmap(w->ring, w->ring_size);
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        log_info("Fanout[%d] worker %d: rx_fd=%d tx_fd=%d frames=%u",
                 fanout_group_id, i, w->rx_fd, w->tx_fd, w->frame_nr);
    }

    return 0;
}

void afpkt_fanout_close(afpkt_fanout_t *fg)
{
    for (int i = 0; i < fg->num_workers; i++) {
        afpkt_worker_t *w = &fg->workers[i];

        if (w->ring) {
            munmap(w->ring, w->ring_size);
            w->ring = NULL;
        }
        if (w->tx_fd >= 0) {
            close(w->tx_fd);
            w->tx_fd = -1;
        }
        if (w->rx_fd >= 0) {
            close(w->rx_fd);
            w->rx_fd = -1;
        }
    }

    memset(fg, 0, sizeof(*fg));
}

/* ================================================== */
/* ================ CACHE INIT ====================== */
/* ================================================== */

void afpkt_fanout_init_cache_outbound(afpkt_fanout_t *fg, const app_context_t *ctx)
{
    for (size_t i = 0; i < ctx->cfg.wan_count && i < MAX_WANS; i++) {
        const char *ifname = ctx->cfg.wans[i].ifname;
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            log_error("Cache outbound: Failed to get ifindex for WAN '%s'", ifname);
            continue;
        }

        unsigned char mac[6];
        if (system_get_if_hwaddr(ifname, mac) != 0) {
            log_error("Cache outbound: Failed to get MAC for WAN '%s'", ifname);
            continue;
        }

        fg->wans[i].ifindex = ifidx;
        memcpy(fg->wans[i].src_mac, mac, 6);
        fg->wans[i].valid = 1;

        log_info("Cache outbound: WAN[%zu] %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 i, ifname, ifidx,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void afpkt_fanout_init_cache_inbound(afpkt_fanout_t *fg, const app_context_t *ctx)
{
    const char *local_if = ctx->cfg.local_if;
    int local_idx = if_nametoindex(local_if);
    unsigned char local_mac[6];

    if (local_idx > 0 && system_get_if_hwaddr(local_if, local_mac) == 0) {
        fg->local.ifindex = local_idx;
        memcpy(fg->local.src_mac, local_mac, 6);
        fg->local.valid = 1;

        log_info("Cache inbound: LOCAL %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 local_if, local_idx,
                 local_mac[0], local_mac[1], local_mac[2],
                 local_mac[3], local_mac[4], local_mac[5]);
    } else {
        log_error("Cache inbound: Failed to cache LOCAL interface '%s'", local_if);
    }
}

/* ================================================== */
/* ============ WORKER LOOP OUTBOUND ================ */
/* ================================================== */

void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                 const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;

    log_info("Worker outbound[%d] started", w->id);

    while (*running) {
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 1000) <= 0)
            continue;

        while (1) {
            struct tpacket_hdr *hdr = (struct tpacket_hdr *)
                ((char *)w->ring + (w->frame_idx * RX_FRAME_SIZE));

            if (!(hdr->tp_status & TP_STATUS_USER))
                break;

            unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
            unsigned int len = hdr->tp_len;
            struct ethhdr *eth = (struct ethhdr *)frame;

            /* WAN selection: round-robin per worker */
            int selected_wan = pkt_cnt % ctx->cfg.wan_count;

            if (!fg->wans[selected_wan].valid) {
                hdr->tp_status = TP_STATUS_KERNEL;
                w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
                continue;
            }

            /* Validate dst_mac */
            int is_valid = 0;
            for (int i = 0; i < 6; i++) {
                if (ctx->cfg.wans[selected_wan].dst_mac[i] != 0) {
                    is_valid = 1;
                    break;
                }
            }
            if (!is_valid) {
                log_error("Worker outbound[%d]: Invalid dst_mac for WAN[%d] - all zeros",
                          w->id, selected_wan);
                hdr->tp_status = TP_STATUS_KERNEL;
                w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
                continue;
            }

            /* Rewrite MAC (read from fg->wans cache, read-only -> thread-safe) */
            memcpy(eth->h_source, fg->wans[selected_wan].src_mac, 6);
            memcpy(eth->h_dest, ctx->cfg.wans[selected_wan].dst_mac, 6);

            log_debug("Worker outbound[%d]: src=%02x:%02x:%02x:%02x:%02x:%02x "
                      "dst=%02x:%02x:%02x:%02x:%02x:%02x",
                      w->id,
                      eth->h_source[0], eth->h_source[1], eth->h_source[2],
                      eth->h_source[3], eth->h_source[4], eth->h_source[5],
                      eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                      eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            struct sockaddr_ll sll = {
                .sll_family   = AF_PACKET,
                .sll_protocol = htons(ETH_P_ALL),
                .sll_ifindex  = fg->wans[selected_wan].ifindex,
                .sll_halen    = 6,
            };
            memcpy(sll.sll_addr, eth->h_dest, 6);

            ssize_t n = sendto(w->tx_fd, frame, len, 0,
                              (struct sockaddr *)&sll, sizeof(sll));
            if (n < 0) {
                log_error("Worker outbound[%d]: sendto() WAN[%d] failed: %s",
                          w->id, selected_wan, strerror(errno));
            } else {
                pkt_cnt++;
            }

            hdr->tp_status = TP_STATUS_KERNEL;
            w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
        }

        if (pkt_cnt && (pkt_cnt % 100 == 0)) {
            log_info("Worker outbound[%d] packets=%lu", w->id, pkt_cnt);
        }
    }

    log_info("Worker outbound[%d] stopped, pkt_cnt=%lu", w->id, pkt_cnt);
}

/* ================================================== */
/* ============ WORKER LOOP INBOUND ================= */
/* ================================================== */

void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;

    log_info("Worker inbound[%d] started", w->id);

    while (*running) {
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 1000) <= 0)
            continue;

        while (1) {
            struct tpacket_hdr *hdr = (struct tpacket_hdr *)
                ((char *)w->ring + (w->frame_idx * RX_FRAME_SIZE));

            if (!(hdr->tp_status & TP_STATUS_USER))
                break;

            unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
            unsigned int len = hdr->tp_len;
            struct ethhdr *eth = (struct ethhdr *)frame;

            if (!fg->local.valid) {
                hdr->tp_status = TP_STATUS_KERNEL;
                w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
                continue;
            }

            /* Validate LAN dst_mac */
            int is_valid = 0;
            for (int i = 0; i < 6; i++) {
                if (ctx->cfg.lan.dst_mac[i] != 0) {
                    is_valid = 1;
                    break;
                }
            }
            if (!is_valid) {
                log_error("Worker inbound[%d]: Invalid LAN dst_mac - all zeros", w->id);
                hdr->tp_status = TP_STATUS_KERNEL;
                w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
                continue;
            }

            /* Rewrite L2 header */
            memcpy(eth->h_dest, ctx->cfg.lan.dst_mac, 6);
            memcpy(eth->h_source, fg->local.src_mac, 6);

            log_debug("Worker inbound[%d]: src=%02x:%02x:%02x:%02x:%02x:%02x "
                      "dst=%02x:%02x:%02x:%02x:%02x:%02x",
                      w->id,
                      eth->h_source[0], eth->h_source[1], eth->h_source[2],
                      eth->h_source[3], eth->h_source[4], eth->h_source[5],
                      eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                      eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            struct sockaddr_ll sll = {
                .sll_family   = AF_PACKET,
                .sll_protocol = htons(ETH_P_ALL),
                .sll_ifindex  = fg->local.ifindex,
                .sll_halen    = 6,
            };
            memcpy(sll.sll_addr, ctx->cfg.lan.dst_mac, 6);

            ssize_t n = sendto(w->tx_fd, frame, len, 0,
                              (struct sockaddr *)&sll, sizeof(sll));
            if (n < 0) {
                log_error("Worker inbound[%d]: sendto() LOCAL failed: %s",
                          w->id, strerror(errno));
            } else {
                pkt_cnt++;
            }

            hdr->tp_status = TP_STATUS_KERNEL;
            w->frame_idx = (w->frame_idx + 1) % w->frame_nr;
        }

        if (pkt_cnt && (pkt_cnt % 100 == 0)) {
            log_info("Worker inbound[%d] packets=%lu", w->id, pkt_cnt);
        }
    }

    log_info("Worker inbound[%d] stopped, pkt_cnt=%lu", w->id, pkt_cnt);
}
