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
#define V3_BLOCK_SIZE (1 << 20) /* 2MB Blocks */
#define V3_BLOCK_NR 256          /* 256 blocks = 512MB Ring */
#define V3_FRAME_SIZE 2048

#define TX_BATCH_SIZE 1024

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

void afpkt_fanout_close(afpkt_fanout_t *)
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
    /* Create one UDP socket per tunnel and cache sockaddr_in for VXLAN TX */
    fg->tunnel_count = ctx->cfg.ne_tunnel_count;
    for (size_t i = 0; i < fg->tunnel_count && i < MAX_NE_TUNNELS; i++)
    {
        /* Create UDP socket for this tunnel */
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            log_error("Cache outbound: Failed to create UDP socket for tunnel[%zu]: %s",
                      i, strerror(errno));
            fg->tunnel_udp_fds[i] = -1;
            continue;
        }

        /* Increase TX buffer to absorb bursts (16 MB) */
        int sndbuf = 16 * 1024 * 1024;
        setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));

        fg->tunnel_udp_fds[i] = udp_fd;

        /* Cache sockaddr_in with remote IP and VXLAN port */
        memset(&fg->tunnel_addrs[i], 0, sizeof(fg->tunnel_addrs[i]));
        fg->tunnel_addrs[i].sin_family = AF_INET;
        fg->tunnel_addrs[i].sin_port   = htons(VXLAN_PORT);
        if (inet_pton(AF_INET, ctx->cfg.ne_tunnels[i].gateway,
                      &fg->tunnel_addrs[i].sin_addr) != 1) {
            log_error("Cache outbound: Invalid gateway '%s' for tunnel[%zu]",
                      ctx->cfg.ne_tunnels[i].gateway, i);
            close(udp_fd);
            fg->tunnel_udp_fds[i] = -1;
            continue;
        }

        log_info("Cache outbound: TUNNEL[%zu] %s -> %s:%d (udp_fd=%d)",
                 i, ctx->cfg.ne_tunnels[i].ifname,
                 ctx->cfg.ne_tunnels[i].gateway, VXLAN_PORT, udp_fd);
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
 * Outbound: capture from local_if → encapsulate in VXLAN → send via UDP
 * Each original L2 frame gets a VXLAN header prepended, then sent to
 * the tunnel's remote_ip:4789 via a standard UDP socket.
 * Kernel handles Outer IP/UDP/MAC headers and checksums automatically.
 */
void afpkt_worker_loop_outbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long captured_cnt = 0;
    unsigned long ip_pkts = 0;
    log_info("Worker outbound[%d] started (VXLAN UDP Encapsulation)", w->id);

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0)
    {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        return;
    }

    /* ---- Pre-build a VXLAN header template (8 bytes, reused for every packet) ---- */
    vxlan_hdr_t vxlan_template;
    vxlan_hdr_build(&vxlan_template, VXLAN_DEFAULT_VNI);

    /* ---- Fragment buffer pool (heap, reusable after each flush) ---- */
    /* Each frag slot: VXLAN_HDR(8) + frag header area from frag_split (~128 bytes) */
    uint8_t *frag_arena = malloc((size_t)TX_BATCH_SIZE * 2048);
    if (!frag_arena) {
        log_error("Worker outbound[%d]: failed to allocate frag arena", w->id);
        return;
    }

    /* ---- Scratch buffer for VXLAN encapsulation of non-fragmented packets ---- */
    uint8_t *vxlan_buf = malloc(2048 + VXLAN_HDR_SIZE);
    if (!vxlan_buf) {
        log_error("Worker outbound[%d]: failed to allocate vxlan_buf", w->id);
        free(frag_arena);
        return;
    }

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

                if (fg->tunnel_udp_fds[tunnel_idx] < 0)
                    goto next_pkt;

                pkt_cnt++;

                if (frag_need_split((uint32_t)len)) {
                    /* Fragment the original frame, then VXLAN-encap each piece */
                    uint8_t *h1 = frag_arena;
                    uint8_t *h2 = frag_arena + 1024;
                    uint32_t h1_len, h2_len;
                    const uint8_t *p1, *p2;
                    uint32_t p1_len, p2_len;

                    if (frag_split(frame, (uint32_t)len, h1, &h1_len, &p1, &p1_len, h2, &h2_len, &p2, &p2_len) == 0) {
                        /* Fragment 1: VXLAN + frag_header + payload1 */
                        uint8_t pkt1[2048 + VXLAN_HDR_SIZE];
                        memcpy(pkt1, &vxlan_template, VXLAN_HDR_SIZE);
                        memcpy(pkt1 + VXLAN_HDR_SIZE, h1, h1_len);
                        memcpy(pkt1 + VXLAN_HDR_SIZE + h1_len, p1, p1_len);
                        uint32_t total1 = VXLAN_HDR_SIZE + h1_len + p1_len;

                        sendto(fg->tunnel_udp_fds[tunnel_idx], pkt1, total1, 0,
                               (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                               sizeof(struct sockaddr_in));

                        /* Fragment 2: VXLAN + frag_header + payload2 */
                        uint8_t pkt2[2048 + VXLAN_HDR_SIZE];
                        memcpy(pkt2, &vxlan_template, VXLAN_HDR_SIZE);
                        memcpy(pkt2 + VXLAN_HDR_SIZE, h2, h2_len);
                        memcpy(pkt2 + VXLAN_HDR_SIZE + h2_len, p2, p2_len);
                        uint32_t total2 = VXLAN_HDR_SIZE + h2_len + p2_len;

                        sendto(fg->tunnel_udp_fds[tunnel_idx], pkt2, total2, 0,
                               (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                               sizeof(struct sockaddr_in));
                    }
                } else {
                    /* Non-fragmented: prepend VXLAN header to original frame */
                    memcpy(vxlan_buf, &vxlan_template, VXLAN_HDR_SIZE);
                    memcpy(vxlan_buf + VXLAN_HDR_SIZE, frame, len);
                    uint32_t total = VXLAN_HDR_SIZE + len;

                    sendto(fg->tunnel_udp_fds[tunnel_idx], vxlan_buf, total, 0,
                           (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                           sizeof(struct sockaddr_in));
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(frag_arena);
    free(vxlan_buf);
    log_info("Worker outbound[%d] stopped: captured=%lu ip_pkts=%lu processed=%lu",
             w->id, captured_cnt, ip_pkts, pkt_cnt);
}

/* ================================================== */
/* ============ WORKER LOOP INBOUND ================= */
/* ================================================== */

/*
 * Inbound: receive VXLAN-encapsulated packets from UDP socket → strip VXLAN →
 * reassemble fragments → rewrite MAC → forward to local_if via AF_PACKET.
 *
 * The UDP socket (fg->udp_rx_fd) is bound to port 4789.
 * After stripping the 8-byte VXLAN header, we get the Inner L2 Frame
 * which may or may not be fragmented (Protocol=253 check).
 */
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                               const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long total_pkts = 0;
    unsigned long non_ip = 0;

    log_info("Worker inbound[%d] started (VXLAN UDP Decapsulation)", w->id);

    /* RX buffer for UDP recv */
    uint8_t *rx_buf = malloc(4096);
    if (!rx_buf) {
        log_error("Worker inbound[%d]: failed to allocate rx_buf", w->id);
        return;
    }

    /* ---- Pre-cache sockaddr_ll for LOCAL LAN TX (AF_PACKET) ---- */
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

    /* Reassembly buffer */
    uint8_t *reassem_buf = malloc(4096);
    if (!reassem_buf) {
        log_error("Worker inbound[%d]: failed to allocate reassem_buf", w->id);
        free(rx_buf);
        return;
    }

    while (*running)
    {
        /* Poll the UDP RX socket with timeout */
        struct pollfd pfd = {.fd = fg->udp_rx_fd, .events = POLLIN};
        if (poll(&pfd, 1, 100) <= 0)
            continue;

        /* Receive UDP payload (VXLAN Header + Inner L2 Frame) */
        ssize_t n = recv(fg->udp_rx_fd, rx_buf, 4096, 0);
        if (n <= (ssize_t)VXLAN_HDR_SIZE)
            continue;

        total_pkts++;

        /* Strip VXLAN header (8 bytes) → inner frame starts at rx_buf + 8 */
        uint8_t *inner_frame = rx_buf + VXLAN_HDR_SIZE;
        uint32_t inner_len = (uint32_t)(n - VXLAN_HDR_SIZE);

        if (inner_len < 14)
            continue;

        /* The inner frame is an original L2 Ethernet frame */
        /* Check if it contains our custom fragment (IP Protocol = 253) */
        uint16_t pkt_id;
        uint8_t frag_index;

        if (frag_is_fragment(inner_frame, inner_len, &pkt_id, &frag_index)) {
            if (fg->frag_tbl) {
                uint32_t reassem_len = 0;
                int ret = frag_try_reassemble(fg->frag_tbl, inner_frame, inner_len,
                                              pkt_id, frag_index,
                                              reassem_buf, &reassem_len);
                if (ret == 1) {
                    /* Successfully reassembled — rewrite MAC and send to LAN */
                    uint8_t *ip_data = reassem_buf + 14;
                    int is_ipv4 = ((ip_data[0] >> 4) == 4);
                    if (is_ipv4) {
                        memcpy(reassem_buf, cached_eth_ipv4, 14);
                        sa.sll_protocol = htons(ETH_P_IP);
                    } else {
                        memcpy(reassem_buf, cached_eth_ipv6, 14);
                        sa.sll_protocol = htons(ETH_P_IPV6);
                    }

                    sendto(w->tx_fd, reassem_buf, reassem_len, 0,
                           (struct sockaddr *)&sa, sizeof(sa));
                    pkt_cnt++;
                }
                /* ret == 0: stored fragment, waiting for pair — do nothing */
            }
        } else {
            /* Non-fragmented inner frame — rewrite MAC and send to LAN */
            uint8_t *ip_data = inner_frame + 14;
            if (inner_len <= 14) {
                non_ip++;
                continue;
            }

            int is_ipv4 = ((ip_data[0] >> 4) == 4);
            if (is_ipv4) {
                memcpy(inner_frame, cached_eth_ipv4, 14);
                sa.sll_protocol = htons(ETH_P_IP);
            } else {
                memcpy(inner_frame, cached_eth_ipv6, 14);
                sa.sll_protocol = htons(ETH_P_IPV6);
            }

            sendto(w->tx_fd, inner_frame, inner_len, 0,
                   (struct sockaddr *)&sa, sizeof(sa));
            pkt_cnt++;
        }
    }

    free(rx_buf);
    free(reassem_buf);
    log_info("Worker inbound[%d] stopped: total=%lu non_ip=%lu forwarded=%lu",
             w->id, total_pkts, non_ip, pkt_cnt);
}









