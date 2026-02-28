#define _GNU_SOURCE
#include "userio/afpkt.h"
#include "utils/logger.h"
#include "system/system.h"
#include "proto/mwan_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

/* TPACKET_V3 constants */
#define V3_BLOCK_SIZE (1 << 21) /* 2MB Blocks */
#define V3_BLOCK_NR 64          /* 64 blocks = 128MB Ring */
#define V3_FRAME_SIZE 2048

/* Global outbound sequence counter (shared across all outbound workers) */
static _Atomic uint32_t g_outbound_seq = 0;

/* ================================================== */
/* ============ FANOUT OPEN / CLOSE ================= */
/* ================================================== */

int afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id)
{
    memset(fg, 0, sizeof(*fg));
    fg->num_workers = NUM_WORKERS;
    fg->fanout_group_id = fanout_group_id;

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0)
    {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    for (int i = 0; i < NUM_WORKERS; i++)
    {
        afpkt_worker_t *w = &fg->workers[i];
        w->id = i;

        /* 1. RX socket */
        w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->rx_fd < 0)
        {
            log_error("Fanout[%d] worker %d: socket(RX) failed: %s",
                      fanout_group_id, i, strerror(errno));
            return -1;
        }

        /* 2. Set TPACKET_V3 version */
        int version = TPACKET_V3;
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
        {
            log_error("Fanout[%d] worker %d: setsockopt(PACKET_VERSION=V3) failed: %s",
                      fanout_group_id, i, strerror(errno));
            return -1;
        }

        /* 2a. Ignore outgoing packets */
        int ignore_out = 1;
        setsockopt(w->rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));

        /* 2b. Enable Busy Poll on Socket */
        int busy_poll_us = 50;
        setsockopt(w->rx_fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));

        /* 3. Bind to interface */
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex = ifidx,
        };
        if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0)
        {
            log_error("Fanout[%d] worker %d: bind(%s) failed: %s",
                      fanout_group_id, i, ifname, strerror(errno));
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        /* 4. RX ring V3 setup */
        struct tpacket_req3 req;
        memset(&req, 0, sizeof(req));
        req.tp_block_size = V3_BLOCK_SIZE;
        req.tp_frame_size = V3_FRAME_SIZE;
        req.tp_block_nr = V3_BLOCK_NR;
        req.tp_frame_nr = (V3_BLOCK_SIZE * V3_BLOCK_NR) / V3_FRAME_SIZE;
        req.tp_retire_blk_tov = 3;
        req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING,
                       &req, sizeof(req)) != 0)
        {
            log_error("Fanout[%d] worker %d: PACKET_RX_RING (V3) failed: %s",
                      fanout_group_id, i, strerror(errno));
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        size_t ring_sz = (size_t)req.tp_block_size * req.tp_block_nr;
        w->ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED, w->rx_fd, 0);
        if (w->ring == MAP_FAILED)
        {
            log_error("Fanout[%d] worker %d: mmap failed: %s",
                      fanout_group_id, i, strerror(errno));
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }
        w->ring_size = ring_sz;
        w->block_count = req.tp_block_nr;
        w->current_block = 0;

        /* 5. PACKET_FANOUT — hash-based distribution */
        int fanout_arg = (fanout_group_id & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_FANOUT,
                       &fanout_arg, sizeof(fanout_arg)) != 0)
        {
            log_error("Fanout[%d] worker %d: PACKET_FANOUT failed: %s",
                      fanout_group_id, i, strerror(errno));
            munmap(w->ring, w->ring_size);
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        /* 6. TX socket */
        w->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->tx_fd < 0)
        {
            log_error("Fanout[%d] worker %d: socket(TX) failed: %s",
                      fanout_group_id, i, strerror(errno));
            munmap(w->ring, w->ring_size);
            w->ring = NULL;
            close(w->rx_fd);
            w->rx_fd = -1;
            return -1;
        }

        log_info("Fanout[%d] worker %d: rx_fd=%d tx_fd=%d V3_Blocks=%u",
                 fanout_group_id, i, w->rx_fd, w->tx_fd, w->block_count);
    }

    return 0;
}

/* Open a single RX+TX socket without fanout (for inbound per-tunnel) */
int afpkt_single_open(afpkt_worker_t *w, const char *ifname)
{
    memset(w, 0, sizeof(*w));
    w->rx_fd = -1;
    w->tx_fd = -1;

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0)
    {
        log_error("afpkt_single_open: if_nametoindex(%s) failed", ifname);
        return -1;
    }

    /* RX socket */
    w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (w->rx_fd < 0)
    {
        log_error("afpkt_single_open(%s): socket(RX) failed: %s", ifname, strerror(errno));
        return -1;
    }

    /* TPACKET_V3 */
    int version = TPACKET_V3;
    if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
    {
        log_error("afpkt_single_open(%s): PACKET_VERSION failed: %s", ifname, strerror(errno));
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }

    int ignore_out = 1;
    setsockopt(w->rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));

    int busy_poll_us = 50;
    setsockopt(w->rx_fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));

    /* Bind */
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = ifidx,
    };
    if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0)
    {
        log_error("afpkt_single_open(%s): bind failed: %s", ifname, strerror(errno));
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }

    /* RX ring */
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = V3_BLOCK_SIZE;
    req.tp_frame_size = V3_FRAME_SIZE;
    req.tp_block_nr = V3_BLOCK_NR;
    req.tp_frame_nr = (V3_BLOCK_SIZE * V3_BLOCK_NR) / V3_FRAME_SIZE;
    req.tp_retire_blk_tov = 3;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0)
    {
        log_error("afpkt_single_open(%s): PACKET_RX_RING failed: %s", ifname, strerror(errno));
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }

    size_t ring_sz = (size_t)req.tp_block_size * req.tp_block_nr;
    w->ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED, w->rx_fd, 0);
    if (w->ring == MAP_FAILED)
    {
        log_error("afpkt_single_open(%s): mmap failed: %s", ifname, strerror(errno));
        w->ring = NULL;
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }
    w->ring_size = ring_sz;
    w->block_count = req.tp_block_nr;
    w->current_block = 0;

    /* No FANOUT — single socket per tunnel */

    /* TX socket */
    w->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (w->tx_fd < 0)
    {
        log_error("afpkt_single_open(%s): socket(TX) failed: %s", ifname, strerror(errno));
        munmap(w->ring, w->ring_size);
        w->ring = NULL;
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }

    log_info("afpkt_single_open(%s): rx_fd=%d tx_fd=%d V3_Blocks=%u",
             ifname, w->rx_fd, w->tx_fd, w->block_count);
    return 0;
}

void afpkt_fanout_close(afpkt_fanout_t *fg)
{
    for (int i = 0; i < fg->num_workers; i++)
    {
        afpkt_worker_t *w = &fg->workers[i];

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

    memset(fg, 0, sizeof(*fg));
}

/* ================================================== */
/* ================ CACHE INIT ====================== */
/* ================================================== */

void afpkt_fanout_init_cache_outbound(afpkt_fanout_t *fg, const app_context_t *ctx)
{
    // /* Cache WAN interfaces (kept for reference) */
    // for (size_t i = 0; i < ctx->cfg.wan_count && i < MAX_WANS; i++)
    // {
    //     const char *ifname = ctx->cfg.wans[i].ifname;
    //     int ifidx = if_nametoindex(ifname);
    //     if (ifidx == 0)
    //     {
    //         log_error("Cache outbound: Failed to get ifindex for WAN '%s'", ifname);
    //         continue;
    //     }
    //     unsigned char mac[6];
    //     if (system_get_if_hwaddr(ifname, mac) != 0)
    //     {
    //         log_error("Cache outbound: Failed to get MAC for WAN '%s'", ifname);
    //         continue;
    //     }
    //     fg->wans[i].ifindex = ifidx;
    //     memcpy(fg->wans[i].src_mac, mac, 6);
    //     fg->wans[i].valid = 1;
    //     log_info("Cache outbound: WAN[%zu] %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
    //              i, ifname, ifidx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // }

    /* Cache ne_tunnel interfaces for TX */
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count && i < MAX_NE_TUNNELS; i++)
    {
        const char *ifname = ctx->cfg.ne_tunnels[i].ifname;
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0)
        {
            log_error("Cache outbound: Failed to get ifindex for TUNNEL '%s'", ifname);
            continue;
        }
        unsigned char mac[6];
        if (system_get_if_hwaddr(ifname, mac) != 0)
        {
            log_error("Cache outbound: Failed to get MAC for TUNNEL '%s'", ifname);
            continue;
        }
        fg->tunnels[i].ifindex = ifidx;
        memcpy(fg->tunnels[i].src_mac, mac, 6);
        fg->tunnels[i].valid = 1;
        log_info("Cache outbound: TUNNEL[%zu] %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 i, ifname, ifidx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void afpkt_fanout_init_cache_inbound(afpkt_fanout_t *fg, const app_context_t *ctx)
{
    const char *local_if = ctx->cfg.local_if;
    int local_idx = if_nametoindex(local_if);
    unsigned char local_mac[6];

    if (local_idx > 0 && system_get_if_hwaddr(local_if, local_mac) == 0)
    {
        fg->local.ifindex = local_idx;
        memcpy(fg->local.src_mac, local_mac, 6);
        fg->local.valid = 1;
        log_info("Cache inbound: LOCAL %s: ifindex=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 local_if, local_idx,
                 local_mac[0], local_mac[1], local_mac[2],
                 local_mac[3], local_mac[4], local_mac[5]);
    }
    else
    {
        log_error("Cache inbound: Failed to cache LOCAL interface '%s'", local_if);
    }
}

/* ================================================== */
/* ============ WORKER LOOP OUTBOUND ================ */
/* ================================================== */

/*
 * Outbound: capture from local_if → forward to ne_tunnel (Round Robin)
 * No fragmentation, no custom header insertion (except Ethernet rewrite).
 */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long captured_cnt = 0;
    unsigned long ip_pkts = 0;
    log_info("Worker outbound[%d] started (L3 Forwarding Only)", w->id);

    /* Buffer for building new frames. 1514 (ETH) */
    uint8_t *tx_buf = malloc(2048);
    if (!tx_buf) {
        log_error("Worker outbound[%d]: failed to allocate tx_buf", w->id);
        return;
    }

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0)
    {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        free(tx_buf);
        return;
    }

    while (*running)
    {
        struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 0) == 0)
            continue;

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                captured_cnt++;

                /* Need at least Ethernet header */
                if (len < 14)
                    goto next_pkt;

                struct ethhdr *eth = (struct ethhdr *)frame;

                /* 1. IGNORE MWAN protocol packets to avoid loops */
                if (ntohs(eth->h_proto) == MWAN_ETHERTYPE) {
                    log_debug("Worker outbound[%d]: Ignoring MWAN packet", w->id);
                    goto next_pkt;
                }

                /* 2. IGNORE packets where source MAC is our own LOCAL MAC */
                if (memcmp(eth->h_source, fg->local.src_mac, 6) == 0) {
                    log_debug("Worker outbound[%d]: Ignoring MAC source matched with local MAC", w->id);
                    goto next_pkt;
                }

                /* 3. ONLY process IP packets */
                if (ntohs(eth->h_proto) != ETH_P_IP && ntohs(eth->h_proto) != ETH_P_IPV6) {
                    if (ntohs(eth->h_proto) != 0x0806) { // Bỏ qua ARP log để đỡ nhiễu
                        // log_debug("Worker outbound[%d]: Ignoring non-IP packet (proto: 0x%04x)", w->id, ntohs(eth->h_proto));
                    }
                    goto next_pkt;
                }

                /* Extract IP data */
                uint8_t *ip_data = frame + 14;
                uint16_t ip_len = (uint16_t)(len - 14);

                if (ip_len == 0) {
                    log_debug("Worker outbound[%d]: Ignoring empty IP packet", w->id);
                    goto next_pkt;
                }

                ip_pkts++;

                /* Select tunnel Round-Robin */
                uint32_t seq = atomic_fetch_add(&g_outbound_seq, 1);
                int tunnel_idx = (int)(seq % tunnel_count);

                if (!fg->tunnels[tunnel_idx].valid) {
                    log_debug("Worker outbound[%d]: Invalid tunnel %d selected", w->id, tunnel_idx);
                    goto next_pkt;
                }
                
                pkt_cnt++;

                if (frag_need_split((uint32_t)len)) {
                    uint8_t frag1_pkt[2048];
                    uint32_t frag1_len;
                    uint8_t frag2_pkt[2048];
                    uint32_t frag2_len;

                    if (frag_split(frame, (uint32_t)len, frag1_pkt, &frag1_len, frag2_pkt, &frag2_len) == 0) {
                        /* Send Frag 1 */
                        struct ethhdr *eth_out1 = (struct ethhdr *)frag1_pkt;
                        memcpy(eth_out1->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                        memcpy(eth_out1->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                        eth_out1->h_proto = htons(MWAN_ETHERTYPE);
                        
                        struct sockaddr_ll sa1;
                        memset(&sa1, 0, sizeof(sa1));
                        sa1.sll_family = AF_PACKET;
                        sa1.sll_protocol = htons(MWAN_ETHERTYPE);
                        sa1.sll_ifindex = fg->tunnels[tunnel_idx].ifindex;
                        sa1.sll_halen = 6;
                        memcpy(sa1.sll_addr, eth_out1->h_dest, 6);
                        
                        sendto(w->tx_fd, frag1_pkt, frag1_len, 0, (struct sockaddr *)&sa1, sizeof(sa1));

                        /* Send Frag 2 */
                        struct ethhdr *eth_out2 = (struct ethhdr *)frag2_pkt;
                        memcpy(eth_out2->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                        memcpy(eth_out2->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                        eth_out2->h_proto = htons(MWAN_ETHERTYPE);
                        
                        struct sockaddr_ll sa2;
                        memset(&sa2, 0, sizeof(sa2));
                        sa2.sll_family = AF_PACKET;
                        sa2.sll_protocol = htons(MWAN_ETHERTYPE);
                        sa2.sll_ifindex = fg->tunnels[tunnel_idx].ifindex;
                        sa2.sll_halen = 6;
                        memcpy(sa2.sll_addr, eth_out2->h_dest, 6);
                        
                        sendto(w->tx_fd, frag2_pkt, frag2_len, 0, (struct sockaddr *)&sa2, sizeof(sa2));
                        
                        log_debug("Worker outbound[%d]: FRAGMENTED seq %u to tunnel %d", w->id, seq, tunnel_idx);
                    } else {
                        log_error("Worker outbound[%d]: frag_split failed for pkt_len=%u", w->id, len);
                    }
                } else {
                    struct ethhdr *eth_out = (struct ethhdr *)tx_buf;
                    memcpy(eth_out->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                    memcpy(eth_out->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                    eth_out->h_proto = htons(MWAN_ETHERTYPE); // 0x88B5 for tunnnel

                    /* Copy original IP packet */
                    memcpy(tx_buf + 14, ip_data, ip_len);

                    struct sockaddr_ll sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sll_family = AF_PACKET;
                    sa.sll_protocol = htons(MWAN_ETHERTYPE);
                    sa.sll_ifindex = fg->tunnels[tunnel_idx].ifindex;
                    sa.sll_halen = 6;
                    memcpy(sa.sll_addr, eth_out->h_dest, 6);

                    if (sendto(w->tx_fd, tx_buf, 14 + ip_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                        log_error("Worker outbound[%d]: sendto failed: %s", w->id, strerror(errno));
                    } else {
                        log_debug("Worker outbound[%d]: Forwarded seq %u to tunnel %d (%s) ip_len=%u",
                                   w->id, seq, tunnel_idx, ctx->cfg.ne_tunnels[tunnel_idx].ifname, ip_len);
                    }
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(tx_buf);
    log_info("Worker outbound[%d] stopped: captured=%lu ip_pkts=%lu processed=%lu",
             w->id, captured_cnt, ip_pkts, pkt_cnt);
}

/* ================================================== */
/* ============ WORKER LOOP INBOUND ================= */
/* ================================================== */

/*
 * Inbound: capture from ne_tunnel → forward to local_if
 * No reassembly, no reordering.
 */
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                               const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long total_pkts = 0;
    unsigned long non_mwan = 0;

    log_info("Worker inbound[%d] started (L3 Forwarding Only)", w->id);

    /* TX Buffer */
    uint8_t *tx_buf = malloc(2048);
    if (!tx_buf) {
        log_error("Worker inbound[%d]: failed to allocate tx_buf", w->id);
        return;
    }

    if (!fg->local.valid) {
        log_error("Worker inbound[%d]: Local interface info missing!", w->id);
        free(tx_buf);
        return;
    }

    while (*running)
    {
        struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 0) == 0)
            continue;

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                total_pkts++;
                if (len < 14)
                    goto next_in;

                struct ethhdr *eth = (struct ethhdr *)frame;

                // --- TRACE TẤT CẢ GÓI TIN ---
                log_debug("[INBOUND TRACE] Worker inbound[%d] rcvd len=%u proto=0x%04x MAC dst=%02x:%02x:%02x:%02x:%02x:%02x", 
                          w->id, len, ntohs(eth->h_proto), 
                          eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
                          eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

                /* Only process our protocol */
                if (ntohs(eth->h_proto) != MWAN_ETHERTYPE)
                {
                    non_mwan++;
                    goto next_in;
                }

                /* Extract IP data (Skip Eth header) - Assuming NO mwan_header */
                uint8_t *ip_data = frame + 14;
                uint16_t ip_len = (uint16_t)(len - 14);
                
                if (ip_len == 0) goto next_in;

                pkt_cnt++;

                uint16_t pkt_id;
                uint8_t frag_index;
                
                if (frag_is_fragment(frame, len, &pkt_id, &frag_index)) {
                    uint8_t reassembled[4096];
                    uint32_t reassem_len = 0;
                    if (fg->frag_tbl) {
                        int ret = frag_try_reassemble(fg->frag_tbl, frame, len, pkt_id, frag_index, reassembled, &reassem_len);
                        if (ret == 1) { // successfully reassembled
                            // extract new payload size to send
                            ip_data = reassembled + 14;
                            ip_len = reassem_len - 14;
                            
                            struct ethhdr *eth_out = (struct ethhdr *)tx_buf;
                            memcpy(eth_out->h_source, fg->local.src_mac, 6);
                            memcpy(eth_out->h_dest, ctx->cfg.lan.dst_mac, 6);
                            eth_out->h_proto = ((ip_data[0] >> 4) == 4) ? htons(ETH_P_IP) : htons(ETH_P_IPV6);

                            /* Copy IP data */
                            memcpy(tx_buf + 14, ip_data, ip_len);

                            struct sockaddr_ll sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sll_family = AF_PACKET;
                            sa.sll_protocol = htons(ETH_P_IP);
                            sa.sll_ifindex = fg->local.ifindex;
                            sa.sll_halen = 6;
                            memcpy(sa.sll_addr, eth_out->h_dest, 6);

                            if (sendto(w->tx_fd, tx_buf, 14 + ip_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                                log_error("Worker inbound[%d]: sendto failed (local_if, reassembled): %s", w->id, strerror(errno));
                            } else {
                                log_debug("Worker inbound[%d]: Forwarded REASSEMBLED packet to local LAN (ip_len=%u)", w->id, ip_len);
                            }
                        } else if (ret == 0) {
                             log_debug("Worker inbound[%d]: Stored fragment pkt_id=%u idx=%u", w->id, pkt_id, frag_index);
                        } else {
                             log_debug("Worker inbound[%d]: fragment drop/error pkt_id=%u", w->id, pkt_id);
                        }
                    }
                } else {
                    /* Rewrite Ethernet Header for LAN */
                    struct ethhdr *eth_out = (struct ethhdr *)tx_buf;
                    memcpy(eth_out->h_source, fg->local.src_mac, 6);
                    memcpy(eth_out->h_dest, ctx->cfg.lan.dst_mac, 6);
                    eth_out->h_proto = ((ip_data[0] >> 4) == 4) ? htons(ETH_P_IP) : htons(ETH_P_IPV6);

                    /* Copy IP data */
                    memcpy(tx_buf + 14, ip_data, ip_len);

                    /* Send to local_if */
                    struct sockaddr_ll sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sll_family = AF_PACKET;
                    sa.sll_protocol = htons(ETH_P_IP);
                    sa.sll_ifindex = fg->local.ifindex;
                    sa.sll_halen = 6;
                    memcpy(sa.sll_addr, eth_out->h_dest, 6);

                    if (sendto(w->tx_fd, tx_buf, 14 + ip_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                        log_error("Worker inbound[%d]: sendto failed (local_if): %s", w->id, strerror(errno));
                    } else {
                        log_debug("Worker inbound[%d]: Forwarded packet from tunnel to local LAN (ip_len=%u)", w->id, ip_len);
                    }
                }

            next_in:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(tx_buf);
    log_info("Worker inbound[%d] stopped: total=%lu non_mwan=%lu forwarded=%lu",
             w->id, total_pkts, non_mwan, pkt_cnt);
}
