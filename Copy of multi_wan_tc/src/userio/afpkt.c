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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* TPACKET_V3 constants */
#define V3_BLOCK_SIZE (1 << 21) /* 2MB Blocks */
#define V3_BLOCK_NR 64          /* 64 blocks = 128MB Ring */
#define V3_FRAME_SIZE 2048

#define TX_BATCH_SIZE 512

/* Per-worker RR counter eliminates cross-core atomic contention.
 * Old global atomic was a serialization point at high pps. */

/* ================================================== */
/* ============ FANOUT OPEN / CLOSE ================= */
/* ================================================== */

static inline uint32_t calculate_5tuple_hash(const uint8_t *frame, uint32_t len) {
    if (len < 14) return 0;
    
    struct ethhdr *eth = (struct ethhdr *)frame;
    uint16_t h_proto = ntohs(eth->h_proto);
    uint32_t hash = 0;

    if (h_proto == ETH_P_IP) {
        if (len < 14 + sizeof(struct iphdr)) return 0;
        struct iphdr *iph = (struct iphdr *)(frame + 14);
        uint32_t sip = iph->saddr;
        uint32_t dip = iph->daddr;
        uint8_t proto = iph->protocol;
        
        uint16_t sport = 0, dport = 0;
        int iph_len = iph->ihl * 4;
        
        if (proto == IPPROTO_TCP && len >= 14 + iph_len + sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(frame + 14 + iph_len);
            sport = tcph->source;
            dport = tcph->dest;
        } else if (proto == IPPROTO_UDP && len >= 14 + iph_len + sizeof(struct udphdr)) {
            struct udphdr *udph = (struct udphdr *)(frame + 14 + iph_len);
            sport = udph->source;
            dport = udph->dest;
        }
        
        hash = sip ^ dip ^ ((uint32_t)sport << 16 | dport) ^ proto;
    } else if (h_proto == ETH_P_IPV6) {
        if (len < 14 + sizeof(struct ip6_hdr)) return 0;
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(frame + 14);
        uint32_t *s = (uint32_t *)ip6h->ip6_src.s6_addr;
        uint32_t *d = (uint32_t *)ip6h->ip6_dst.s6_addr;
        uint8_t proto = ip6h->ip6_nxt;
        hash = s[3] ^ d[3] ^ proto;
    } else {
        return 0;
    }
    
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    
    return hash;
}

int afpkt_fanout_open(afpkt_fanout_t *fg, const char *ifname, int fanout_group_id, int num_workers)
{
    memset(fg, 0, sizeof(*fg));
    if (num_workers > MAX_FANOUT_WORKERS) num_workers = MAX_FANOUT_WORKERS;
    fg->num_workers = num_workers;
    fg->fanout_group_id = fanout_group_id;

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0)
    {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    for (int i = 0; i < num_workers; i++)
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

        /* 2b. (REMOVED) Enable Busy Poll on Socket
         * We let NIC interrupt CPU naturally to avoid 100% spin
         */
        // int busy_poll_us = 50;
        // setsockopt(w->rx_fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));

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

        /* Increase TX buffer to absorb bursts (16 MB) */
        int sndbuf = 16 * 1024 * 1024;
        setsockopt(w->tx_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));

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

    /* We let NIC interrupt CPU naturally to avoid 100% spin */
    // int busy_poll_us = 50;
    // setsockopt(w->rx_fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));

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

    /* Increase TX buffer to absorb bursts (16 MB) */
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(w->tx_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
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
 * sendmmsg_full(): retry until ALL packets are sent.
 * If kernel TX queue is full, sendmmsg returns fewer than requested.
 * This function retries the remaining packets with a brief pause,
 * implementing BACKPRESSURE: we slow down processing to match TX capacity.
 * This guarantees ZERO packet loss at the application level.
 */
static void sendmmsg_full(int fd, struct mmsghdr *batch, int count) {
    int sent = 0;
    while (sent < count) {
        int ret = sendmmsg(fd, batch + sent, count - sent, 0);
        if (ret > 0) {
            sent += ret;
        } else if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                /* TX queue full — wait briefly then retry (backpressure) */
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 }; /* 100µs */
                nanosleep(&ts, NULL);
            } else {
                /* Real error — break to avoid infinite loop */
                break;
            }
        }
    }
}

/*
 * Outbound: capture from local_if → forward to ne_tunnel (Hash-based)
 * Uses batched sendmmsg() to minimize syscall overhead.
 * Optimizations:
 *   - Pre-cached 14-byte ETH header per tunnel (1 memcpy instead of 2+assign)
 *   - memset tx_batch ONCE per block instead of per-packet
 */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long captured_cnt = 0;
    unsigned long ip_pkts = 0;
    log_info("Worker outbound[%d] started (Batched sendmmsg + FastMAC)", w->id);

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0)
    {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        return;
    }

    /* ---- Pre-cache sockaddr_ll per tunnel (computed ONCE) ---- */
    struct sockaddr_ll cached_sa[MAX_NE_TUNNELS];
    for (size_t t = 0; t < tunnel_count && t < MAX_NE_TUNNELS; t++) {
        memset(&cached_sa[t], 0, sizeof(cached_sa[t]));
        cached_sa[t].sll_family   = AF_PACKET;
        cached_sa[t].sll_protocol = htons(MWAN_ETHERTYPE);
        cached_sa[t].sll_ifindex  = fg->tunnels[t].ifindex;
        cached_sa[t].sll_halen    = 6;
        memcpy(cached_sa[t].sll_addr, ctx->cfg.ne_tunnels[t].dst_mac, 6);
    }

    /* ---- Pre-cache full 14-byte Ethernet header per tunnel ----
     * Layout: [dst_mac (6)] [src_mac (6)] [ethertype (2)]
     * One 14-byte memcpy replaces 2x 6-byte memcpy + 1 ethertype assign */
    uint8_t cached_eth[MAX_NE_TUNNELS][14];
    for (size_t t = 0; t < tunnel_count && t < MAX_NE_TUNNELS; t++) {
        memcpy(cached_eth[t] + 0, ctx->cfg.ne_tunnels[t].dst_mac, 6);    /* h_dest */
        memcpy(cached_eth[t] + 6, fg->tunnels[t].src_mac, 6);            /* h_source */
        cached_eth[t][12] = (uint8_t)(MWAN_ETHERTYPE >> 8);              /* h_proto (BE) */
        cached_eth[t][13] = (uint8_t)(MWAN_ETHERTYPE & 0xFF);
    }

    /* ---- Fragment buffer pool (heap, reusable after each flush) ---- */
    uint8_t *frag_arena = malloc((size_t)TX_BATCH_SIZE * 2048);
    if (!frag_arena) {
        log_error("Worker outbound[%d]: failed to allocate frag arena", w->id);
        return;
    }

    /* ---- Batch TX structures (stack) ---- */
    struct mmsghdr tx_batch[TX_BATCH_SIZE];
    struct iovec   tx_iov[TX_BATCH_SIZE];

    while (*running)
    {
        struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 100) <= 0)
            continue;

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            /* ---- Batch state for this block ---- */
            int batch_n = 0;   /* messages queued */
            int frag_idx = 0;  /* next free slot in frag_arena */

            /* OPT: Clear batch array ONCE per block instead of per-packet */
            memset(tx_batch, 0, sizeof(tx_batch));

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                captured_cnt++;

                if (len < 14)
                    goto next_pkt;

                struct ethhdr *eth = (struct ethhdr *)frame;
                uint16_t h_proto = ntohs(eth->h_proto);

                if (h_proto == MWAN_ETHERTYPE)
                    goto next_pkt;

                if (memcmp(eth->h_source, fg->local.src_mac, 6) == 0)
                    goto next_pkt;

                if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
                    goto next_pkt;

                if (len <= 14)
                    goto next_pkt;

                ip_pkts++;

                uint32_t hash = calculate_5tuple_hash(frame, len);
                int tunnel_idx = hash % tunnel_count;

                if (!fg->tunnels[tunnel_idx].valid)
                    goto next_pkt;

                pkt_cnt++;

                if (frag_need_split((uint32_t)len)) {
                    /* Need 2 batch slots + 2 frag buffers */
                    if (batch_n + 2 > TX_BATCH_SIZE || frag_idx + 2 > TX_BATCH_SIZE) {
                        if (batch_n > 0)
                            sendmmsg_full(w->tx_fd, tx_batch, batch_n);
                        batch_n = 0;
                        frag_idx = 0;
                        memset(tx_batch, 0, sizeof(tx_batch));
                    }

                    uint8_t *f1 = frag_arena + (size_t)frag_idx * 2048;
                    uint8_t *f2 = frag_arena + (size_t)(frag_idx + 1) * 2048;
                    uint32_t f1_len, f2_len;

                    if (frag_split(frame, (uint32_t)len, f1, &f1_len, f2, &f2_len) == 0) {
                        /* OPT: Single 14-byte copy for entire ETH header */
                        memcpy(f1, cached_eth[tunnel_idx], 14);
                        memcpy(f2, cached_eth[tunnel_idx], 14);

                        tx_iov[batch_n] = (struct iovec){ .iov_base = f1, .iov_len = f1_len };
                        tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                        tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                        tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                        tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                        batch_n++;

                        tx_iov[batch_n] = (struct iovec){ .iov_base = f2, .iov_len = f2_len };
                        tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                        tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                        tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                        tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                        batch_n++;

                        frag_idx += 2;
                    }
                } else {
                    /* Non-fragmented: batch directly from ring buffer (zero-copy) */
                    if (batch_n >= TX_BATCH_SIZE) {
                        sendmmsg_full(w->tx_fd, tx_batch, batch_n);
                        batch_n = 0;
                        frag_idx = 0;
                        memset(tx_batch, 0, sizeof(tx_batch));
                    }

                    /* OPT: Single 14-byte copy for entire ETH header */
                    memcpy(frame, cached_eth[tunnel_idx], 14);

                    tx_iov[batch_n] = (struct iovec){ .iov_base = frame, .iov_len = len };
                    tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                    tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                    tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                    tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                    batch_n++;
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            /* ---- Flush remaining batch BEFORE releasing block ---- */
            if (batch_n > 0)
                sendmmsg_full(w->tx_fd, tx_batch, batch_n);

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(frag_arena);
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

    /* ---- Pre-cache sockaddr_ll cho LOCAL ---- */
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = fg->local.ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, ctx->cfg.lan.dst_mac, 6);

    /* ---- Pre-cache full 14-byte Ethernet headers for LOCAL ---- */
    uint8_t cached_eth_ipv4[14];
    memcpy(cached_eth_ipv4 + 0, ctx->cfg.lan.dst_mac, 6);
    memcpy(cached_eth_ipv4 + 6, fg->local.src_mac, 6);
    cached_eth_ipv4[12] = (uint8_t)((ETH_P_IP) >> 8);
    cached_eth_ipv4[13] = (uint8_t)((ETH_P_IP) & 0xFF);

    uint8_t cached_eth_ipv6[14];
    memcpy(cached_eth_ipv6 + 0, ctx->cfg.lan.dst_mac, 6);
    memcpy(cached_eth_ipv6 + 6, fg->local.src_mac, 6);
    cached_eth_ipv6[12] = (uint8_t)((ETH_P_IPV6) >> 8);
    cached_eth_ipv6[13] = (uint8_t)((ETH_P_IPV6) & 0xFF);

    /* ---- Fragment buffer pool cho inbound ---- */
    uint8_t *frag_arena = malloc((size_t)TX_BATCH_SIZE * 2048);
    if (!frag_arena) {
        log_error("Worker inbound[%d]: failed to allocate frag arena", w->id);
        return;
    }

    /* ---- Batch TX structures ---- */
    struct mmsghdr tx_batch[TX_BATCH_SIZE];
    struct iovec   tx_iov[TX_BATCH_SIZE];

    while (*running)
    {
        /* BLOCKING POLL with TIMEOUT: Đợi ngắt từ NIC nhưng timeout mỗi 100ms
         * Để luồng có cơ hội thức dậy và kiểm tra biến *running khi có lệnh tắt (Ctrl+C)
         */
        struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 100) <= 0) {
            continue;
        }

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            int batch_n = 0;
            int frag_idx = 0;

            /* OPT: Clear batch array ONCE per block */
            memset(tx_batch, 0, sizeof(tx_batch));

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                total_pkts++;
                if (len < 14)
                    goto next_in;

                struct ethhdr *eth = (struct ethhdr *)frame;

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
                    if (fg->frag_tbl) {
                        /* Dam bao dung luong batch truoc khi goi reassemble */
                        if (batch_n >= TX_BATCH_SIZE || frag_idx >= TX_BATCH_SIZE) {
                            sendmmsg_full(w->tx_fd, tx_batch, batch_n);
                            batch_n = 0;
                            frag_idx = 0;
                            memset(tx_batch, 0, sizeof(tx_batch));
                        }

                        uint8_t *reassembled = frag_arena + (size_t)frag_idx * 2048;
                        uint32_t reassem_len = 0;

                        int ret = frag_try_reassemble(fg->frag_tbl, frame, len, pkt_id, frag_index, reassembled, &reassem_len);
                        if (ret == 1) { // successfully reassembled
                            // extract new payload size to send
                            ip_data = reassembled + 14;
                            ip_len = reassem_len - 14;
                            
                            /* OPT: Fast 14-byte MAC rewrite */
                            int is_ipv4 = ((ip_data[0] >> 4) == 4);
                            if (is_ipv4) {
                                memcpy(reassembled, cached_eth_ipv4, 14);
                                sa.sll_protocol = htons(ETH_P_IP);
                            } else {
                                memcpy(reassembled, cached_eth_ipv6, 14);
                                sa.sll_protocol = htons(ETH_P_IPV6);
                            }

                            tx_iov[batch_n] = (struct iovec){ .iov_base = reassembled, .iov_len = reassem_len };
                            tx_batch[batch_n].msg_hdr.msg_name    = &sa;
                            tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                            tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                            tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                            batch_n++;
                            frag_idx++;
                        }
                    }
                } else {
                    if (batch_n >= TX_BATCH_SIZE) {
                        sendmmsg_full(w->tx_fd, tx_batch, batch_n);
                        batch_n = 0;
                        frag_idx = 0;
                        memset(tx_batch, 0, sizeof(tx_batch));
                    }

                    /* ZERO-COPY OPT: Rewrite Ethernet Header directly on the ring buffer frame */
                    int is_ipv4 = ((ip_data[0] >> 4) == 4);
                    if (is_ipv4) {
                        memcpy(frame, cached_eth_ipv4, 14);
                        sa.sll_protocol = htons(ETH_P_IP);
                    } else {
                        memcpy(frame, cached_eth_ipv6, 14);
                        sa.sll_protocol = htons(ETH_P_IPV6);
                    }

                    tx_iov[batch_n] = (struct iovec){ .iov_base = frame, .iov_len = 14 + ip_len };
                    tx_batch[batch_n].msg_hdr.msg_name    = &sa;
                    tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                    tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                    tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                    batch_n++;
                }


            next_in:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            if (batch_n > 0) {
                sendmmsg_full(w->tx_fd, tx_batch, batch_n);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(tx_buf);
    free(frag_arena);
    log_info("Worker inbound[%d] stopped: total=%lu non_mwan=%lu forwarded=%lu",
             w->id, total_pkts, non_mwan, pkt_cnt);
}

/* ================================================== */
/* ============ PIPELINE: OPEN / CLOSE ============== */
/* ================================================== */

int afpkt_pipeline_open(afpkt_pipeline_t *pl, const char *ifname, int num_tx_workers)
{
    memset(pl, 0, sizeof(*pl));
    if (num_tx_workers > MAX_TX_WORKERS)
        num_tx_workers = MAX_TX_WORKERS;
    pl->num_tx_workers = num_tx_workers;

    for (int i = 0; i < MAX_TX_WORKERS; i++)
        pl->tx_fds[i] = -1;

    /* Single RX socket with TPACKET_V3 (no fanout) */
    if (afpkt_single_open(&pl->rx, ifname) != 0) {
        log_error("Pipeline: failed to open RX on %s", ifname);
        return -1;
    }

    /* Allocate per-worker queues */
    for (int i = 0; i < num_tx_workers; i++) {
        pl->queues[i] = malloc(sizeof(struct pkt_queue));
        if (!pl->queues[i]) {
            log_error("Pipeline: failed to alloc queue[%d]", i);
            afpkt_pipeline_close(pl);
            return -1;
        }
        pkt_queue_init(pl->queues[i]);
    }

    /* Per-worker TX sockets */
    for (int i = 0; i < num_tx_workers; i++) {
        pl->tx_fds[i] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (pl->tx_fds[i] < 0) {
            log_error("Pipeline: failed to open TX socket[%d]: %s", i, strerror(errno));
            afpkt_pipeline_close(pl);
            return -1;
        }
    }

    log_info("Pipeline opened: RX on %s, %d TX workers, queue capacity=%d",
             ifname, num_tx_workers, PKT_QUEUE_CAPACITY);
    return 0;
}

void afpkt_pipeline_close(afpkt_pipeline_t *pl)
{
    /* Close RX */
    if (pl->rx.ring) {
        munmap(pl->rx.ring, pl->rx.ring_size);
        pl->rx.ring = NULL;
    }
    if (pl->rx.rx_fd >= 0) { close(pl->rx.rx_fd); pl->rx.rx_fd = -1; }
    if (pl->rx.tx_fd >= 0) { close(pl->rx.tx_fd); pl->rx.tx_fd = -1; }

    /* Free queues */
    for (int i = 0; i < MAX_TX_WORKERS; i++) {
        free(pl->queues[i]);
        pl->queues[i] = NULL;
    }

    /* Close TX sockets */
    for (int i = 0; i < MAX_TX_WORKERS; i++) {
        if (pl->tx_fds[i] >= 0) {
            close(pl->tx_fds[i]);
            pl->tx_fds[i] = -1;
        }
    }
}

/* ================================================== */
/* ============ PIPELINE: RX DISTRIBUTE ============= */
/* ================================================== */

void afpkt_rx_distribute_loop(afpkt_worker_t *rx_w,
                               const afpkt_fanout_t *fg,
                               struct pkt_queue **queues, int num_queues,
                               volatile int *running)
{
    unsigned long total = 0, pushed = 0, dropped = 0;
    // unsigned long prev_pushed = 0, prev_dropped = 0;
    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    log_info("Pipeline RX thread started (distributing to %d TX workers)", num_queues);

    while (*running)
    {
        /* BLOCKING POLL with TIMEOUT: Đợi ngắt từ NIC nhưng timeout mỗi 100ms
         * Để luồng có cơ hội thức dậy và kiểm tra biến *running khi có lệnh tắt (Ctrl+C)
         */
        struct pollfd pfd = {.fd = rx_w->rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 100) <= 0) {
            /* Periodic stats even when idle */
            clock_gettime(CLOCK_MONOTONIC, &ts_now);
            double elapsed = (ts_now.tv_sec - ts_start.tv_sec) + (ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;
            if (elapsed >= 2.0) {
                // unsigned long delta_push = pushed - prev_pushed;
                // unsigned long delta_drop = dropped - prev_dropped;
                // log_info("[RX STATS] push_rate=%lu pkt/s | q_full_drops=%lu/s | total_dropped=%lu",
                //          (unsigned long)(delta_push / elapsed),
                //          (unsigned long)(delta_drop / elapsed), dropped);
                // prev_pushed = pushed;
                // prev_dropped = dropped;
                clock_gettime(CLOCK_MONOTONIC, &ts_start);
            }
            continue;
        }

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)rx_w->ring + (rx_w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                total++;

                if (len < 14)
                    goto rx_next;

                struct ethhdr *eth = (struct ethhdr *)frame;
                uint16_t h_proto = ntohs(eth->h_proto);

                if (h_proto == MWAN_ETHERTYPE)
                    goto rx_next;
                if (memcmp(eth->h_source, fg->local.src_mac, 6) == 0)
                    goto rx_next;
                if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
                    goto rx_next;
                if (len <= 14)
                    goto rx_next;

                uint32_t hash = calculate_5tuple_hash(frame, len);
                int start_q_idx = hash % num_queues;
                int q_idx = start_q_idx;

                /* SPILLOVER FAILOVER / BACKPRESSURE:
                 * If the target queue is full, try the next queue (spillover to another worker)
                 * to prevent 100% Core bottleneck on a single TX worker. */
                int pushed_ok = 0;
                while (*running) {
                    if (pkt_queue_push(queues[q_idx], frame, len, hash) == 0) {
                        pushed_ok = 1;
                        break;
                    }
                    
                    /* Queue full -> Spillover to the next worker's queue */
                    q_idx = (q_idx + 1) % num_queues;
                    
                    /* If we have checked all queues and ALL are full, yield CPU and retry */
                    if (q_idx == start_q_idx) {
                        sched_yield(); /* Yield to consumers */
                    }
                }
                if (pushed_ok) pushed++;

            rx_next:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            rx_w->current_block = (rx_w->current_block + 1) % rx_w->block_count;
        }

        /* Periodic stats under load */
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        double elapsed = (ts_now.tv_sec - ts_start.tv_sec) + (ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;
        if (elapsed >= 2.0) {
            // unsigned long delta_push = pushed - prev_pushed;
            // unsigned long delta_drop = dropped - prev_dropped;
            // log_info("[RX STATS] push_rate=%lu pkt/s | q_full_drops=%lu/s | total_dropped=%lu",
            //          (unsigned long)(delta_push / elapsed),
            //          (unsigned long)(delta_drop / elapsed), dropped);
            // prev_pushed = pushed;
            // prev_dropped = dropped;
            clock_gettime(CLOCK_MONOTONIC, &ts_start);
        }
    }

    log_info("Pipeline RX stopped: total=%lu pushed=%lu q_full_drops=%lu", total, pushed, dropped);
}

/* ================================================== */
/* ============ PIPELINE: TX WORKER ================= */
/* ================================================== */

void afpkt_tx_worker_loop(int worker_id, struct pkt_queue *q, int tx_fd,
                           const afpkt_fanout_t *fg,
                           const app_context_t *ctx,
                           volatile int *running)
{
    unsigned long pkt_cnt = 0;
    // unsigned long prev_pkt_cnt = 0;
    unsigned long send_calls = 0;
    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    log_info("Pipeline TX worker[%d] started", worker_id);

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0) {
        log_error("TX worker[%d]: no tunnels configured!", worker_id);
        return;
    }

    /* Pre-cache sockaddr_ll per tunnel */
    struct sockaddr_ll cached_sa[MAX_NE_TUNNELS];
    for (size_t t = 0; t < tunnel_count && t < MAX_NE_TUNNELS; t++) {
        memset(&cached_sa[t], 0, sizeof(cached_sa[t]));
        cached_sa[t].sll_family   = AF_PACKET;
        cached_sa[t].sll_protocol = htons(MWAN_ETHERTYPE);
        cached_sa[t].sll_ifindex  = fg->tunnels[t].ifindex;
        cached_sa[t].sll_halen    = 6;
        memcpy(cached_sa[t].sll_addr, ctx->cfg.ne_tunnels[t].dst_mac, 6);
    }

    uint8_t *frag_arena = malloc((size_t)TX_BATCH_SIZE * 2048);
    if (!frag_arena) {
        log_error("TX worker[%d]: alloc frag_arena failed", worker_id);
        return;
    }

    struct mmsghdr tx_batch[TX_BATCH_SIZE];
    struct iovec   tx_iov[TX_BATCH_SIZE];
    uint32_t local_read = atomic_load_explicit(&q->read_idx, memory_order_relaxed);

    while (*running)
    {
        uint32_t write_pos = pkt_queue_write_pos(q);

        if (local_read == write_pos) {
            /* Nhường thời gian thực thi lại cho hđh tránh bào mòn CPU khi rỗi */
            usleep(10);
            continue;
        }

        int batch_n = 0;
        int frag_idx = 0;

        /* Drain available packets from queue into batch */
        while (local_read != write_pos && batch_n < TX_BATCH_SIZE - 1)
        {
            struct pkt_slot *slot = pkt_queue_slot_at(q, local_read);
            uint8_t *frame = slot->data;
            uint32_t len = slot->len;
            uint32_t hash = slot->hash;

            int tunnel_idx = hash % tunnel_count;

            if (!fg->tunnels[tunnel_idx].valid) {
                local_read = (local_read + 1) & PKT_QUEUE_MASK;
                continue;
            }

            pkt_cnt++;

            if (frag_need_split(len)) {
                if (batch_n + 2 > TX_BATCH_SIZE || frag_idx + 2 > TX_BATCH_SIZE)
                    break;

                uint8_t *f1 = frag_arena + (size_t)frag_idx * 2048;
                uint8_t *f2 = frag_arena + (size_t)(frag_idx + 1) * 2048;
                uint32_t f1_len, f2_len;

                if (frag_split(frame, len, f1, &f1_len, f2, &f2_len) == 0) {
                    struct ethhdr *eh1 = (struct ethhdr *)f1;
                    memcpy(eh1->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                    memcpy(eh1->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                    eh1->h_proto = htons(MWAN_ETHERTYPE);

                    struct ethhdr *eh2 = (struct ethhdr *)f2;
                    memcpy(eh2->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                    memcpy(eh2->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                    eh2->h_proto = htons(MWAN_ETHERTYPE);

                    tx_iov[batch_n] = (struct iovec){ .iov_base = f1, .iov_len = f1_len };
                    memset(&tx_batch[batch_n], 0, sizeof(tx_batch[batch_n]));
                    tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                    tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                    tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                    tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                    batch_n++;

                    tx_iov[batch_n] = (struct iovec){ .iov_base = f2, .iov_len = f2_len };
                    memset(&tx_batch[batch_n], 0, sizeof(tx_batch[batch_n]));
                    tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                    tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                    tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                    tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                    batch_n++;

                    frag_idx += 2;
                }
            } else {
                if (batch_n >= TX_BATCH_SIZE)
                    break;

                struct ethhdr *eth_out = (struct ethhdr *)frame;
                memcpy(eth_out->h_source, fg->tunnels[tunnel_idx].src_mac, 6);
                memcpy(eth_out->h_dest, ctx->cfg.ne_tunnels[tunnel_idx].dst_mac, 6);
                eth_out->h_proto = htons(MWAN_ETHERTYPE);

                tx_iov[batch_n] = (struct iovec){ .iov_base = frame, .iov_len = len };
                memset(&tx_batch[batch_n], 0, sizeof(tx_batch[batch_n]));
                tx_batch[batch_n].msg_hdr.msg_name    = &cached_sa[tunnel_idx];
                tx_batch[batch_n].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                tx_batch[batch_n].msg_hdr.msg_iov     = &tx_iov[batch_n];
                tx_batch[batch_n].msg_hdr.msg_iovlen  = 1;
                batch_n++;
            }

            local_read = (local_read + 1) & PKT_QUEUE_MASK;
        }

        if (batch_n > 0) {
            sendmmsg_full(tx_fd, tx_batch, batch_n);
            send_calls++;
        }

        pkt_queue_consume_to(q, local_read);
    }

    free(frag_arena);
    log_info("Pipeline TX worker[%d] stopped: processed=%lu", worker_id, pkt_cnt);
}
