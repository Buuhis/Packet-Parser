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

/* ---- OPTIMIZED tuning constants for high throughput ---- */
/* Phase 1: Quick Wins - Increased buffer sizes */
#define RX_BLOCK_SIZE   (1 << 22)   /* 4MB (was 1MB) */
#define RX_FRAME_SIZE   4096         /* 4KB (was 2KB) */
#define RX_BLOCK_NR     256          /* 256 blocks (was 64) */

/* Total buffer: 1GB, ~262,144 frames */
/* At 1.5GB/s: ~0.67 seconds of buffering */

/* Socket buffer sizes */
#define SOCKET_RCVBUF   (128 * 1024 * 1024)  /* 128MB */
#define SOCKET_SNDBUF   (128 * 1024 * 1024)  /* 128MB */

/* Batch processing */
#define BATCH_SIZE      64

struct afpkt_ctx {
    int fd;
    int tx_fd;  /* TX socket for sending to WAN interfaces */
    void *ring;
    size_t ring_size;
    unsigned int frame_nr;
    unsigned int frame_idx;

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
    
    /* Statistics */
    unsigned long tx_packets;
    unsigned long tx_errors;
    unsigned long rx_packets;
};

/* Outbound context (LOCAL -> WAN) */
static struct afpkt_ctx g_ctx;

/* Inbound context (WAN -> LOCAL) */
static struct afpkt_ctx g_ctx_inbound;

/* -------------------------------------------------- */

static int set_socket_buffers(int fd)
{
    int rcvbuf = SOCKET_RCVBUF;
    int sndbuf = SOCKET_SNDBUF;
    
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        log_error("Failed to set SO_RCVBUF: %s", strerror(errno));
        return -1;
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        log_error("Failed to set SO_SNDBUF: %s", strerror(errno));
        return -1;
    }
    
    log_info("Socket buffers set: RX=%dMB, TX=%dMB", 
             SOCKET_RCVBUF / (1024*1024), 
             SOCKET_SNDBUF / (1024*1024));
    
    return 0;
}

static int enable_packet_loss_tracking(int fd)
{
    int val = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_LOSS, &val, sizeof(val)) != 0) {
        log_error("Failed to enable PACKET_LOSS tracking: %s", strerror(errno));
        return -1;
    }
    log_info("PACKET_LOSS tracking enabled");
    return 0;
}

/* -------------------------------------------------- */

int afpkt_open_rx(const char *ifname)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        log_error("socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    /* OPTIMIZATION: Set socket buffers BEFORE binding */
    if (set_socket_buffers(fd) != 0) {
        close(fd);
        return -1;
    }

    /* Enable packet loss tracking */
    enable_packet_loss_tracking(fd);

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

    /* setup RX ring with OPTIMIZED sizes */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));

    req.tp_block_size = RX_BLOCK_SIZE;
    req.tp_frame_size = RX_FRAME_SIZE;
    req.tp_block_nr   = RX_BLOCK_NR;
    req.tp_frame_nr   =
        ((unsigned long)RX_BLOCK_SIZE * RX_BLOCK_NR) / RX_FRAME_SIZE;

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
    g_ctx.tx_packets = 0;
    g_ctx.tx_errors = 0;
    g_ctx.rx_packets = 0;

    /* Create TX socket for sending packets to WAN interfaces */
    g_ctx.tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_ctx.tx_fd < 0) {
        log_error("socket(AF_PACKET TX) failed: %s", strerror(errno));
        munmap(ring, ring_sz);
        close(fd);
        return -1;
    }

    /* OPTIMIZATION: Set TX socket buffers */
    if (set_socket_buffers(g_ctx.tx_fd) != 0) {
        munmap(ring, ring_sz);
        close(fd);
        close(g_ctx.tx_fd);
        return -1;
    }

    log_info("AF_PACKET RX ready on %s (frames=%u, buffer=%luMB)",
             ifname, g_ctx.frame_nr, ring_sz / (1024*1024));

    return fd;
}

/* -------------------------------------------------- */

int afpkt_poll_and_forward(int fd, const app_context_t *ctx)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    /* OPTIMIZATION: Shorter timeout for lower latency */
    int ret = poll(&pfd, 1, 100);  /* 100ms instead of 1000ms */
    if (ret <= 0)
        return 0;

    int processed = 0;
    
    while (1) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr *)((char *)g_ctx.ring + (g_ctx.frame_idx * RX_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER))
            break;

        g_ctx.rx_packets++;

        /* L2 frame start */
        unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
        unsigned int  len    = hdr->tp_len;
        struct ethhdr *eth = (struct ethhdr *)frame;

        int selected_wan = 1;

        unsigned char src_mac[6];

        if (g_ctx.wans[selected_wan].valid) {
            memcpy(src_mac, g_ctx.wans[selected_wan].src_mac, 6);
        } else {
            if (system_get_if_hwaddr(ctx->cfg.wans[selected_wan].ifname,
                                      src_mac) != 0) {
                /* OPTIMIZATION: Removed log_error from hot path */
                hdr->tp_status = TP_STATUS_KERNEL;
                g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
                g_ctx.tx_errors++;
                continue;
            }
        }

        /* validate dst_mac once */
        int is_valid = 0;
        for (int i = 0; i < 6; i++) {
            if (ctx->cfg.wans[selected_wan].dst_mac[i] != 0) {
                is_valid = 1;
                break;
            }
        }
        if (!is_valid) {
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
            g_ctx.tx_errors++;
            continue;
        }
        
        /* OPTIMIZATION: Removed debug logging from hot path */
        memcpy(eth->h_source, src_mac, 6);
        memcpy(eth->h_dest, ctx->cfg.wans[selected_wan].dst_mac, 6);

        unsigned int wan_ifindex = 0;
 
        if (g_ctx.wans[selected_wan].valid) {
            wan_ifindex = g_ctx.wans[selected_wan].ifindex;
        } else {
            wan_ifindex = if_nametoindex(ctx->cfg.wans[selected_wan].ifname);
        }
        
        if(wan_ifindex == 0){
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
            g_ctx.tx_errors++;
            continue;
        }

        struct sockaddr_ll sll = {
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex  = wan_ifindex,
            .sll_halen    = 6,
        };
        memcpy(sll.sll_addr, eth->h_dest, 6);

        /* Send */
        ssize_t n = sendto(g_ctx.tx_fd, frame, len, 0,
                          (struct sockaddr *)&sll, sizeof(sll));
        if (n < 0) {
            g_ctx.tx_errors++;
        } else {
            g_ctx.tx_packets++;
        }

        hdr->tp_status = TP_STATUS_KERNEL;
        g_ctx.frame_idx = (g_ctx.frame_idx + 1) % g_ctx.frame_nr;
        processed++;
    }

    /* OPTIMIZATION: Log less frequently (every 10000 packets) */
    if (g_ctx.tx_packets && (g_ctx.tx_packets % 10000 == 0)) {
        log_info("AF_PACKET FWD: tx=%lu rx=%lu errors=%lu (loss=%.2f%%)",
                 g_ctx.tx_packets, g_ctx.rx_packets, g_ctx.tx_errors,
                 (g_ctx.tx_errors * 100.0) / g_ctx.rx_packets);
    }

    return processed;
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

    log_info("AF_PACKET closed: tx=%lu rx=%lu errors=%lu",
             g_ctx.tx_packets, g_ctx.rx_packets, g_ctx.tx_errors);

    memset(&g_ctx, 0, sizeof(g_ctx));
}

/* ================================================== */
/* ============== INBOUND (WAN -> LOCAL) ============ */
/* ================================================== */

int afpkt_open_rx_inbound(const char *ifname)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        log_error("socket(AF_PACKET) inbound failed: %s", strerror(errno));
        return -1;
    }

    /* OPTIMIZATION: Set socket buffers */
    if (set_socket_buffers(fd) != 0) {
        close(fd);
        return -1;
    }

    enable_packet_loss_tracking(fd);

    /* bind to interface */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_nametoindex(ifname),
    };

    if (sll.sll_ifindex == 0) {
        log_error("if_nametoindex(%s) inbound failed", ifname);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        log_error("bind(%s) inbound failed: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    /* setup RX ring with OPTIMIZED sizes */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));

    req.tp_block_size = RX_BLOCK_SIZE;
    req.tp_frame_size = RX_FRAME_SIZE;
    req.tp_block_nr   = RX_BLOCK_NR;
    req.tp_frame_nr   =
        ((unsigned long)RX_BLOCK_SIZE * RX_BLOCK_NR) / RX_FRAME_SIZE;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) != 0) {
        log_error("PACKET_RX_RING inbound failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    size_t ring_sz = req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_sz,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        log_error("mmap RX ring inbound failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    g_ctx_inbound.fd        = fd;
    g_ctx_inbound.ring      = ring;
    g_ctx_inbound.ring_size = ring_sz;
    g_ctx_inbound.frame_nr  = req.tp_frame_nr;
    g_ctx_inbound.frame_idx = 0;
    g_ctx_inbound.tx_packets = 0;
    g_ctx_inbound.tx_errors = 0;
    g_ctx_inbound.rx_packets = 0;

    /* Create TX socket for sending packets to LOCAL interface */
    g_ctx_inbound.tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_ctx_inbound.tx_fd < 0) {
        log_error("socket(AF_PACKET TX) inbound failed: %s", strerror(errno));
        munmap(ring, ring_sz);
        close(fd);
        return -1;
    }

    /* OPTIMIZATION: Set TX socket buffers */
    if (set_socket_buffers(g_ctx_inbound.tx_fd) != 0) {
        munmap(ring, ring_sz);
        close(fd);
        close(g_ctx_inbound.tx_fd);
        return -1;
    }

    log_info("AF_PACKET RX inbound ready on %s (frames=%u, buffer=%luMB)",
             ifname, g_ctx_inbound.frame_nr, ring_sz / (1024*1024));

    return fd;
}

int afpkt_poll_and_forward_inbound(int fd, const app_context_t *ctx)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    /* OPTIMIZATION: Shorter timeout */
    int ret = poll(&pfd, 1, 100);
    if (ret <= 0)
        return 0;

    int processed = 0;

    while (1) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr *)((char *)g_ctx_inbound.ring +
                                   (g_ctx_inbound.frame_idx * RX_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER))
            break;

        g_ctx_inbound.rx_packets++;

        /* L2 frame start */
        unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
        unsigned int  len    = hdr->tp_len;
        struct ethhdr *eth = (struct ethhdr *)frame;

        unsigned char src_mac[6];
        
        if (g_ctx_inbound.local.valid) {
            memcpy(src_mac, g_ctx_inbound.local.src_mac, 6);
        } else {
            if (system_get_if_hwaddr(ctx->cfg.local_if,
                                      src_mac) != 0) {
                hdr->tp_status = TP_STATUS_KERNEL;
                g_ctx_inbound.frame_idx =
                    (g_ctx_inbound.frame_idx + 1) % g_ctx_inbound.frame_nr;
                g_ctx_inbound.tx_errors++;
                continue;
            }
        }

        /* validate LAN dst_mac once */
        int is_valid = 0;
        for (int i = 0; i < 6; i++) {
            if (ctx->cfg.lan.dst_mac[i] != 0) {
                is_valid = 1;
                break;
            }
        }

        if (!is_valid) {
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx_inbound.frame_idx =
                (g_ctx_inbound.frame_idx + 1) % g_ctx_inbound.frame_nr;
            g_ctx_inbound.tx_errors++;
            continue;
        }

        /* Rewrite L2 header */
        memcpy(eth->h_dest, ctx->cfg.lan.dst_mac, 6);
        memcpy(eth->h_source, src_mac, 6);

        unsigned int local_ifindex = 0;
        
        if (g_ctx_inbound.local.valid) {
            local_ifindex = g_ctx_inbound.local.ifindex;
        } else {
            local_ifindex = if_nametoindex(ctx->cfg.local_if);
        }

        if (local_ifindex == 0) {
            hdr->tp_status = TP_STATUS_KERNEL;
            g_ctx_inbound.frame_idx =
                (g_ctx_inbound.frame_idx + 1) % g_ctx_inbound.frame_nr;
            g_ctx_inbound.tx_errors++;
            continue;
        }
        
        /* Send */
        struct sockaddr_ll sll = {
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex  = local_ifindex,
            .sll_halen    = 6,
        };
        memcpy(sll.sll_addr, ctx->cfg.lan.dst_mac, 6);
        
        ssize_t n = sendto(g_ctx_inbound.tx_fd, frame, len, 0,
                          (struct sockaddr *)&sll, sizeof(sll));
        if (n < 0) {
            g_ctx_inbound.tx_errors++;
        } else {
            g_ctx_inbound.tx_packets++;
        }

        /* mark frame as free */
        hdr->tp_status = TP_STATUS_KERNEL;
        g_ctx_inbound.frame_idx =
            (g_ctx_inbound.frame_idx + 1) % g_ctx_inbound.frame_nr;
        processed++;
    }

    /* OPTIMIZATION: Log less frequently */
    if (g_ctx_inbound.tx_packets && (g_ctx_inbound.tx_packets % 10000 == 0)) {
        log_info("AF_PACKET INBOUND: tx=%lu rx=%lu errors=%lu (loss=%.2f%%)",
                 g_ctx_inbound.tx_packets, g_ctx_inbound.rx_packets, 
                 g_ctx_inbound.tx_errors,
                 (g_ctx_inbound.tx_errors * 100.0) / g_ctx_inbound.rx_packets);
    }

    return processed;
}

void afpkt_close_inbound(int fd)
{
    if (g_ctx_inbound.ring)
        munmap(g_ctx_inbound.ring, g_ctx_inbound.ring_size);

    if (g_ctx_inbound.tx_fd >= 0)
        close(g_ctx_inbound.tx_fd);

    if (fd >= 0)
        close(fd);

    log_info("AF_PACKET INBOUND closed: tx=%lu rx=%lu errors=%lu",
             g_ctx_inbound.tx_packets, g_ctx_inbound.rx_packets, 
             g_ctx_inbound.tx_errors);

    memset(&g_ctx_inbound, 0, sizeof(g_ctx_inbound));
}

/* ================================================== */
/* ================== INIT CACHE ==================== */
/* ================================================== */

void afpkt_init_cache(const app_context_t *ctx)
{
    /* 1. Init Outbound Context Cache (g_ctx) - WAN interfaces */
    for (size_t i = 0; i < ctx->cfg.wan_count && i < MAX_WANS; i++) {
        const char *ifname = ctx->cfg.wans[i].ifname;
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            log_error("Cache: Failed to get ifindex for WAN '%s'", ifname);
            continue;
        }

        unsigned char mac[6];
        if (system_get_if_hwaddr(ifname, mac) != 0) {
            log_error("afpkt_init_cache: Failed to get MAC for WAN '%s'", ifname);
            continue;
        }

        g_ctx.wans[i].ifindex = ifidx;
        memcpy(g_ctx.wans[i].src_mac, mac, 6);
        g_ctx.wans[i].valid = 1;

        log_info("Cache: Cached WAN %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 ifname, ifidx,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /* 2. Init Inbound Context Cache (g_ctx_inbound) - LOCAL interface */
    const char *local_if = ctx->cfg.local_if;
    int local_idx = if_nametoindex(local_if);
    unsigned char local_mac[6];
    if (local_idx > 0 && system_get_if_hwaddr(local_if, local_mac) == 0) {
        g_ctx_inbound.local.ifindex = local_idx;
        memcpy(g_ctx_inbound.local.src_mac, local_mac, 6);
        g_ctx_inbound.local.valid = 1;

        log_info("Cache: Cached LOCAL %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 local_if, local_idx,
                 local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
    } else {
        log_error("Cache: Failed to cache LOCAL interface '%s'", local_if);
    }
}
