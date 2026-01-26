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

struct afpkt_ctx {
    int fd;
    int tx_fd;  /* TX socket for sending to WAN interfaces */
    void *ring;
    size_t ring_size;
    unsigned int frame_nr;
    unsigned int frame_idx;
};

static struct afpkt_ctx g_ctx;

/* -------------------------------------------------- */

int afpkt_open_rx(const char *ifname)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        log_error("socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    /* bind to interface */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_nametoindex(ifname),
    };

    if (sll.sll_ifindex == 0) {
        log_error("if_nametoindex(%s) failed", ifname);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        log_error("bind(%s) failed: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    /* setup RX ring */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));

    req.tp_block_size = RX_BLOCK_SIZE;
    req.tp_frame_size = RX_FRAME_SIZE;
    req.tp_block_nr   = RX_BLOCK_NR;
    req.tp_frame_nr   =
        (RX_BLOCK_SIZE * RX_BLOCK_NR) / RX_FRAME_SIZE;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) != 0) {
        log_error("PACKET_RX_RING failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    size_t ring_sz = req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_sz,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        log_error("mmap RX ring failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    g_ctx.fd        = fd;
    g_ctx.ring      = ring;
    g_ctx.ring_size = ring_sz;
    g_ctx.frame_nr  = req.tp_frame_nr;
    g_ctx.frame_idx = 0;

    /* Create TX socket for sending packets to WAN interfaces */
    g_ctx.tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_ctx.tx_fd < 0) {
        log_error("socket(AF_PACKET TX) failed: %s", strerror(errno));
        munmap(ring, ring_sz);
        close(fd);
        return -1;
    }

    log_info("AF_PACKET RX ready on %s (frames=%u)",
             ifname, g_ctx.frame_nr);

    return fd;
}

/* -------------------------------------------------- */

int afpkt_poll_and_count(int fd)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    static unsigned long pkt_cnt = 0;

    int ret = poll(&pfd, 1, 1000);
    if (ret <= 0)
        return 0;

    while (1) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr *)(
                (char *)g_ctx.ring +
                (g_ctx.frame_idx * RX_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER))
            break;

        pkt_cnt++;

        /* mark frame as free */
        hdr->tp_status = TP_STATUS_KERNEL;
        g_ctx.frame_idx =
            (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
    }

    if (pkt_cnt && (pkt_cnt % 10 == 0)) {
        log_info("AF_PACKET RX packets=%lu", pkt_cnt);
    }

    return pkt_cnt;
}

int afpkt_poll_and_forward(int fd, const app_context_t *ctx)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    static unsigned long pkt_cnt = 0;

    int ret = poll(&pfd, 1, 1000);
    if (ret <= 0)
        return 0;

    while (1) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr *)((char *)g_ctx.ring + (g_ctx.frame_idx * RX_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER))
            break;

        /* L2 frame start */
        unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
        unsigned int  len    = hdr->tp_len;   /* includes Ethernet header */
        struct ethhdr *eth = (struct ethhdr *)frame;

        /* 7A-A5: tạm chọn WAN0 */
        int selected_wan = 0;

        unsigned char src_mac[6];
        if (system_get_if_hwaddr(ctx->cfg.wans[selected_wan].ifname, src_mac) != 0) {
            log_error("Failed to get MAC for WAN[%d] interface '%s', dropping packet",
                        selected_wan, ctx->cfg.wans[selected_wan].ifname);
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
            continue;
        }

        /* Validate dst_mac */
        int is_valid_mac = 0;
        for (int i = 0; i < 6; i++) {
            if (ctx->cfg.wans[selected_wan].dst_mac[i] != 0) {
                is_valid_mac = 1;
                break;
            }
        }

        if (!is_valid_mac) {
            log_error("Invalid dst_mac for WAN[%d] - all zeros, dropping packet",
                            selected_wan);
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
            continue;
        }

        /* dst_mac lấy từ config.env */  
        memcpy(eth->h_dest, ctx->cfg.wans[selected_wan].dst_mac, 6);
        log_debug("Setting dst_mac = %02x:%02x:%02x:%02x:%02x:%02x",
          eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
          eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        
        /* src_mac lấy runtime từ wan interface */
        memcpy(eth->h_source, src_mac, 6);

        log_debug("Forwarding packet: src_mac=%02x:%02x:%02x:%02x:%02x:%02x, "
          "dst_mac=%02x:%02x:%02x:%02x:%02x:%02x",
          eth->h_source[0], eth->h_source[1], eth->h_source[2],
          eth->h_source[3], eth->h_source[4], eth->h_source[5],
          eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
          eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

        /* Send packet to WAN interface using sendto() */
        unsigned int wan_ifindex = if_nametoindex(ctx->cfg.wans[selected_wan].ifname);
        if (wan_ifindex == 0) {
            log_error("Failed to get ifindex for WAN[%d] '%s'",
                      selected_wan, ctx->cfg.wans[selected_wan].ifname);
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
            continue;
        }

        struct sockaddr_ll sll = {
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex  = wan_ifindex,
            .sll_halen    = 6,
        };
        memcpy(sll.sll_addr, eth->h_dest, 6);

        ssize_t n = sendto(g_ctx.tx_fd, frame, len, 0,
                          (struct sockaddr *)&sll, sizeof(sll));
        if (n < 0) {
            log_error("sendto() to WAN[%d] '%s' failed: %s",
                      selected_wan, ctx->cfg.wans[selected_wan].ifname,
                      strerror(errno));
        } else {
            pkt_cnt++;
        }

        /* mark frame as free */
        hdr->tp_status = TP_STATUS_KERNEL;
        g_ctx.frame_idx =
            (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
    }

    if (pkt_cnt && (pkt_cnt % 10 == 0)) {
        log_info("AF_PACKET FWD packets=%lu", pkt_cnt);
    }

    return (int)pkt_cnt;
}

/* -------------------------------------------------- */

void afpkt_close(int fd)
{
    if (g_ctx.ring)
        munmap(g_ctx.ring, g_ctx.ring_size);

    if (g_ctx.tx_fd >= 0)
        close(g_ctx.tx_fd);

    if (fd >= 0)
        close(fd);

    memset(&g_ctx, 0, sizeof(g_ctx));
}

