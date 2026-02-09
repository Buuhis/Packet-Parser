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
#define V3_BLOCK_SIZE   (1 << 21) /* 2MB Blocks */
#define V3_BLOCK_NR     64        /* 64 blocks = 128MB Ring */
#define V3_FRAME_SIZE   2048

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

        /* 2. Set TPACKET_V3 version */
        int version = TPACKET_V3;
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
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

        /* 4. RX ring V3 setup */
        struct tpacket_req3 req;
        memset(&req, 0, sizeof(req));
        req.tp_block_size = V3_BLOCK_SIZE;
        req.tp_frame_size = V3_FRAME_SIZE;
        req.tp_block_nr   = V3_BLOCK_NR;
        req.tp_frame_nr   = (V3_BLOCK_SIZE * V3_BLOCK_NR) / V3_FRAME_SIZE;
        req.tp_retire_blk_tov = 10;
        req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING,
                       &req, sizeof(req)) != 0) {
            log_error("Fanout[%d] worker %d: PACKET_RX_RING (V3) failed: %s",
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
        w->block_count = req.tp_block_nr;
        w->current_block = 0;

        /* 5. PACKET_FANOUT — hash-based distribution */
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

        /* 6. TX socket */
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
    if (ifidx == 0) {
        log_error("afpkt_single_open: if_nametoindex(%s) failed", ifname);
        return -1;
    }

    /* RX socket */
    w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (w->rx_fd < 0) {
        log_error("afpkt_single_open(%s): socket(RX) failed: %s", ifname, strerror(errno));
        return -1;
    }

    /* TPACKET_V3 */
    int version = TPACKET_V3;
    if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
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
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifidx,
    };
    if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
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
    req.tp_block_nr   = V3_BLOCK_NR;
    req.tp_frame_nr   = (V3_BLOCK_SIZE * V3_BLOCK_NR) / V3_FRAME_SIZE;
    req.tp_retire_blk_tov = 10;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
        log_error("afpkt_single_open(%s): PACKET_RX_RING failed: %s", ifname, strerror(errno));
        close(w->rx_fd);
        w->rx_fd = -1;
        return -1;
    }

    size_t ring_sz = (size_t)req.tp_block_size * req.tp_block_nr;
    w->ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED, w->rx_fd, 0);
    if (w->ring == MAP_FAILED) {
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
    if (w->tx_fd < 0) {
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
    /* Cache WAN interfaces (kept for reference) */
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
                 i, ifname, ifidx, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /* Cache ne_tunnel interfaces for TX */
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count && i < MAX_NE_TUNNELS; i++) {
        const char *ifname = ctx->cfg.ne_tunnels[i].ifname;
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            log_error("Cache outbound: Failed to get ifindex for TUNNEL '%s'", ifname);
            continue;
        }
        unsigned char mac[6];
        if (system_get_if_hwaddr(ifname, mac) != 0) {
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

/*
 * Outbound: capture from local_if → fragment → send to ne_tunnel (RR by seq)
 *
 * Wire format sent: [Eth(tunnel MAC, etype=0x88B5)][mwan_hdr][IP data chunk]
 */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                 const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    log_info("Worker outbound[%d] started (V3 + Fragment)", w->id);

    /* Scratch buffers for building fragment frames */
    /* Max frame: Eth(14) + mwan_hdr(8) + chunk(1410) = 1432 */
    uint8_t frag_frames[MWAN_MAX_FRAGS][14 + MWAN_HDR_SIZE + MWAN_MAX_CHUNK];

    struct mmsghdr msgs[128];  /* Enough for 64 packets × 2 frags each */
    struct iovec iovs[128];
    struct sockaddr_ll sas[128];

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0) {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        return;
    }

    while (*running) {
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 0) == 0)
            continue;

        while (*running) {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            int batch_cnt = 0;

            for (int i = 0; i < num_pkts; i++) {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                /* Need at least Ethernet header */
                if (len < 14) goto next_pkt;

                /* Extract IP data (skip original Ethernet header) */
                uint8_t *ip_data = frame + 14;
                uint16_t ip_len  = (uint16_t)(len - 14);

                if (ip_len == 0) goto next_pkt;

                /* Assign global sequence and select tunnel */
                uint32_t seq = atomic_fetch_add(&g_outbound_seq, 1);
                int tunnel_idx = (int)(seq % tunnel_count);

                if (!fg->tunnels[tunnel_idx].valid) goto next_pkt;

                /* Fragment */
                mwan_frag_t frags[MWAN_MAX_FRAGS];
                int nfrags = mwan_fragment(ip_data, ip_len, seq, frags);
                if (nfrags <= 0) goto next_pkt;

                /* Build and enqueue each fragment frame */
                for (int f = 0; f < nfrags; f++) {
                    /* Use rotating scratch buffer index */
                    int buf_idx = batch_cnt % MWAN_MAX_FRAGS;
                    uint8_t *out = frag_frames[buf_idx];

                    /* Ethernet header */
                    struct ethhdr *eth_out = (struct ethhdr *)out;
                    memcpy(eth_out->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                    memcpy(eth_out->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                    eth_out->h_proto = htons(MWAN_ETHERTYPE);

                    /* mwan header (network byte order for seq and total_len) */
                    mwan_hdr_t *mh = (mwan_hdr_t *)(out + 14);
                    mh->seq        = htonl(frags[f].hdr.seq);
                    mh->frag_idx   = frags[f].hdr.frag_idx;
                    mh->frag_count = frags[f].hdr.frag_count;
                    mh->total_len  = htons(frags[f].hdr.total_len);

                    /* Payload chunk */
                    memcpy(out + 14 + MWAN_HDR_SIZE, frags[f].ip_chunk, frags[f].chunk_len);

                    uint16_t frame_len = 14 + MWAN_HDR_SIZE + frags[f].chunk_len;

                    /* Enqueue for sendmmsg */
                    iovs[batch_cnt].iov_base = out;
                    iovs[batch_cnt].iov_len  = frame_len;

                    memset(&sas[batch_cnt], 0, sizeof(struct sockaddr_ll));
                    sas[batch_cnt].sll_family   = AF_PACKET;
                    sas[batch_cnt].sll_protocol = htons(MWAN_ETHERTYPE);
                    sas[batch_cnt].sll_ifindex  = fg->tunnels[tunnel_idx].ifindex;
                    sas[batch_cnt].sll_halen    = 6;
                    memcpy(sas[batch_cnt].sll_addr, eth_out->h_dest, 6);

                    memset(&msgs[batch_cnt], 0, sizeof(struct mmsghdr));
                    msgs[batch_cnt].msg_hdr.msg_name    = &sas[batch_cnt];
                    msgs[batch_cnt].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                    msgs[batch_cnt].msg_hdr.msg_iov     = &iovs[batch_cnt];
                    msgs[batch_cnt].msg_hdr.msg_iovlen  = 1;

                    batch_cnt++;

                    if (batch_cnt == 128) {
                        int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                        if (n > 0) pkt_cnt += n;
                        batch_cnt = 0;
                    }
                }

next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            if (batch_cnt > 0) {
                int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                if (n > 0) pkt_cnt += n;
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    log_info("Worker outbound[%d] stopped, pkt_cnt=%lu", w->id, pkt_cnt);
}

/* ================================================== */
/* ============ WORKER LOOP INBOUND ================= */
/* ================================================== */

/*
 * Inbound: capture from ne_tunnel → parse mwan_hdr → reassemble → insert reorder
 *
 * Each inbound worker handles ONE ne_tunnel (no fanout, single socket).
 * Reassembly is per-worker (no locks). Completed packets go into shared reorder buffer.
 */
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running,
                                reorder_ctx_t *reorder)
{
    (void)fg;  /* Not used for inbound — output goes to reorder buffer */

    unsigned long pkt_cnt = 0;
    unsigned long frag_cnt = 0;
    log_info("Worker inbound[%d] started (V3 + Reassembly)", w->id);

    reasm_table_t reasm;
    reasm_table_init(&reasm);

    uint64_t last_expire = mwan_now_ns();

    while (*running) {
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 0) == 0) {
            /* Periodically expire stale reassembly entries */
            uint64_t now = mwan_now_ns();
            if (now - last_expire > REASM_TIMEOUT_NS) {
                reasm_table_expire(&reasm, now);
                last_expire = now;
            }
            continue;
        }

        while (*running) {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++) {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                /* Need Eth header + mwan_hdr minimum */
                if (len < 14 + MWAN_HDR_SIZE) goto next_in;

                struct ethhdr *eth = (struct ethhdr *)frame;

                /* Only process our protocol */
                if (ntohs(eth->h_proto) != MWAN_ETHERTYPE) goto next_in;

                /* Parse mwan header */
                mwan_hdr_t *mh = (mwan_hdr_t *)(frame + 14);
                mwan_hdr_t hdr_host = {
                    .seq        = ntohl(mh->seq),
                    .frag_idx   = mh->frag_idx,
                    .frag_count = mh->frag_count,
                    .total_len  = ntohs(mh->total_len),
                };

                uint8_t *chunk = frame + 14 + MWAN_HDR_SIZE;
                uint16_t chunk_len = (uint16_t)(len - 14 - MWAN_HDR_SIZE);

                frag_cnt++;

                if (hdr_host.frag_count == 1) {
                    /* No fragmentation — forward directly to reorder buffer */
                    reorder_insert(reorder, hdr_host.seq, chunk, chunk_len);
                    pkt_cnt++;
                } else {
                    /* Fragmented — reassemble */
                    uint8_t *out_data = NULL;
                    uint16_t out_len = 0;
                    int rc = reasm_table_insert(&reasm, &hdr_host,
                                                chunk, chunk_len,
                                                &out_data, &out_len);
                    if (rc == 1) {
                        /* Reassembly complete */
                        reorder_insert(reorder, hdr_host.seq, out_data, out_len);
                        pkt_cnt++;
                    }
                }

next_in:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }

        /* Periodic expire */
        uint64_t now = mwan_now_ns();
        if (now - last_expire > REASM_TIMEOUT_NS) {
            reasm_table_expire(&reasm, now);
            last_expire = now;
        }
    }
    log_info("Worker inbound[%d] stopped, pkt_cnt=%lu frags=%lu", w->id, pkt_cnt, frag_cnt);
}
