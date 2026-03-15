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
    /*
     * Create one UDP socket per tunnel for outbound sendto() only.
     * No bind() — Kernel assigns an ephemeral source port automatically.
     * The destination address (remote gateway:port) is cached for sendto().
     */
    fg->tunnel_count = ctx->cfg.ne_tunnel_count;
    for (size_t i = 0; i < fg->tunnel_count && i < MAX_NE_TUNNELS; i++)
    {
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            log_error("Cache outbound: Failed to create UDP socket for tunnel[%zu]: %s",
                      i, strerror(errno));
            fg->tunnel_udp_fds[i] = -1;
            continue;
        }

        int sndbuf = 16 * 1024 * 1024;
        setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));

        fg->tunnel_udp_fds[i] = udp_fd;

        /* Cache sockaddr_in with remote IP and port for sendto() */
        memset(&fg->tunnel_addrs[i], 0, sizeof(fg->tunnel_addrs[i]));
        fg->tunnel_addrs[i].sin_family = AF_INET;
        fg->tunnel_addrs[i].sin_port   = htons(ctx->cfg.ne_tunnels[i].port);
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
                 ctx->cfg.ne_tunnels[i].gateway,
                 ctx->cfg.ne_tunnels[i].port, udp_fd);
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
 * Outbound: capture from local_if → encapsulate in VXLAN → send via SOCK_DGRAM
 *
 * If the original Ethernet frame > FRAG_INNER_MAX (1410 bytes):
 *   - Split the raw frame into 2 halves
 *   - Fragment 1: VXLAN(frag=FIRST, pkt_id) + first half of frame bytes
 *   - Fragment 2: VXLAN(frag=LAST,  pkt_id) + second half of frame bytes
 *
 * Otherwise:
 *   - VXLAN(frag=NONE) + whole frame
 *
 * The kernel handles Outer IP/UDP/MAC headers automatically via SOCK_DGRAM.
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

    /* Scratch buffer for VXLAN encapsulation */
    uint8_t *vxlan_buf = malloc(2048 + VXLAN_HDR_SIZE);
    if (!vxlan_buf) {
        log_error("Worker outbound[%d]: failed to allocate vxlan_buf", w->id);
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

                /* DEBUG: log first few IP packets */
                if (ip_pkts <= 5) {
                    struct iphdr *dbg_ip = (struct iphdr *)(frame + 14);
                    log_info("OUT[%d] IP pkt #%lu: len=%u proto=0x%04x src=%08x dst=%08x",
                             w->id, ip_pkts, len, h_proto,
                             ntohl(dbg_ip->saddr), ntohl(dbg_ip->daddr));
                }

                uint32_t hash = calculate_5tuple_hash(frame, len);
                int tunnel_idx = hash % tunnel_count;

                if (fg->tunnel_udp_fds[tunnel_idx] < 0)
                    goto next_pkt;

                pkt_cnt++;

                /* DEBUG: log sendto details for first few */
                if (pkt_cnt <= 5) {
                    log_info("OUT[%d] sendto tunnel[%d] fd=%d len=%u frag=%s",
                             w->id, tunnel_idx, fg->tunnel_udp_fds[tunnel_idx], len,
                             frag_need_split((uint32_t)len) ? "YES" : "NO");
                }

                if (frag_need_split((uint32_t)len)) {
                    /* Split the raw Ethernet frame into 2 halves */
                    uint16_t pkt_id = frag_next_pkt_id();
                    uint32_t half1 = len / 2;
                    uint32_t half2 = len - half1;

                    /* Fragment 1: VXLAN(frag=FIRST) + first half of frame */
                    vxlan_hdr_t vx1;
                    vxlan_hdr_build_frag(&vx1, VXLAN_DEFAULT_VNI, pkt_id, VXLAN_FRAG_FIRST);
                    uint8_t pkt1[2048];
                    memcpy(pkt1, &vx1, VXLAN_HDR_SIZE);
                    memcpy(pkt1 + VXLAN_HDR_SIZE, frame, half1);

                    ssize_t rc1 = sendto(fg->tunnel_udp_fds[tunnel_idx], pkt1,
                           VXLAN_HDR_SIZE + half1, 0,
                           (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                           sizeof(struct sockaddr_in));
                    if (rc1 < 0 && pkt_cnt <= 5)
                        log_error("OUT[%d] frag1 sendto failed: %s", w->id, strerror(errno));

                    /* Fragment 2: VXLAN(frag=LAST) + second half of frame */
                    vxlan_hdr_t vx2;
                    vxlan_hdr_build_frag(&vx2, VXLAN_DEFAULT_VNI, pkt_id, VXLAN_FRAG_LAST);
                    uint8_t pkt2[2048];
                    memcpy(pkt2, &vx2, VXLAN_HDR_SIZE);
                    memcpy(pkt2 + VXLAN_HDR_SIZE, frame + half1, half2);

                    ssize_t rc2 = sendto(fg->tunnel_udp_fds[tunnel_idx], pkt2,
                           VXLAN_HDR_SIZE + half2, 0,
                           (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                           sizeof(struct sockaddr_in));
                    if (rc2 < 0 && pkt_cnt <= 5)
                        log_error("OUT[%d] frag2 sendto failed: %s", w->id, strerror(errno));
                } else {
                    /* Non-fragmented: VXLAN(frag=NONE) + whole frame */
                    vxlan_hdr_t vx;
                    vxlan_hdr_build_frag(&vx, VXLAN_DEFAULT_VNI, 0, VXLAN_FRAG_NONE);
                    memcpy(vxlan_buf, &vx, VXLAN_HDR_SIZE);
                    memcpy(vxlan_buf + VXLAN_HDR_SIZE, frame, len);

                    ssize_t rc = sendto(fg->tunnel_udp_fds[tunnel_idx], vxlan_buf,
                           VXLAN_HDR_SIZE + len, 0,
                           (struct sockaddr *)&fg->tunnel_addrs[tunnel_idx],
                           sizeof(struct sockaddr_in));
                    if (rc < 0 && pkt_cnt <= 5)
                        log_error("OUT[%d] sendto failed: %s", w->id, strerror(errno));
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
    free(vxlan_buf);
    log_info("OUT[%d] FINAL: captured=%lu ip_pkts=%lu forwarded=%lu",
             w->id, captured_cnt, ip_pkts, pkt_cnt);
}

/* ================================================== */
/* ============ WORKER LOOP INBOUND ================= */
/* ================================================== */

/*
 * Inbound: capture raw frames via AF_PACKET on ALL interfaces
 *          → filter for IPv4/UDP packets matching tunnel destination ports
 *          → strip Outer Ethernet(14) + Outer IP(20+) + Outer UDP(8) headers
 *          → read 8-byte VXLAN header for pkt_id and frag_index
 *          → reassemble fragments if needed
 *          → rewrite Inner MAC → forward to local_if via AF_PACKET TX
 */
void afpkt_worker_loop_inbound(afpkt_worker_t *w, const afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long total_pkts = 0;
    unsigned long filtered = 0;

    log_info("Worker inbound[%d] started (AF_PACKET VXLAN Decapsulation)", w->id);

    /* ---- Build set of tunnel ports to filter for ---- */
    uint16_t tunnel_ports[MAX_NE_TUNNELS];
    size_t tunnel_port_count = 0;
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        int port = ctx->cfg.ne_tunnels[i].port;
        int dup = 0;
        for (size_t j = 0; j < tunnel_port_count; j++) {
            if (tunnel_ports[j] == (uint16_t)port) { dup = 1; break; }
        }
        if (!dup && tunnel_port_count < MAX_NE_TUNNELS) {
            tunnel_ports[tunnel_port_count++] = (uint16_t)port;
            log_info("Inbound filter: listening for UDP dst port %d", port);
        }
    }

    /* ---- Open AF_PACKET RX socket (all interfaces) ---- */
    int rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx_fd < 0) {
        log_error("Worker inbound[%d]: cannot create AF_PACKET RX socket: %s",
                  w->id, strerror(errno));
        return;
    }

    /* Ignore packets sent by our own machine (avoid loops) */
    int ignore_out = 1;
    setsockopt(rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));

    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(rx_fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf));

    /* ---- Allocate buffers ---- */
    uint8_t *rx_buf = malloc(4096);
    uint8_t *reassem_buf = malloc(4096);
    if (!rx_buf || !reassem_buf) {
        log_error("Worker inbound[%d]: malloc failed", w->id);
        if (rx_buf) free(rx_buf);
        if (reassem_buf) free(reassem_buf);
        close(rx_fd);
        return;
    }

    /* ---- Pre-cache sockaddr_ll for LOCAL LAN TX (AF_PACKET) ---- */
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = fg->local.ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, ctx->cfg.lan.dst_mac, 6);

    /* Pre-cache full 14-byte Ethernet headers for LOCAL */
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

    struct pollfd pfd = {.fd = rx_fd, .events = POLLIN};

    while (*running)
    {
        if (poll(&pfd, 1, 100) <= 0)
            continue;

        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(rx_fd, rx_buf, 4096, 0, (struct sockaddr *)&from, &fromlen);
        if (n <= 0) continue;

        /* Skip if packet is outgoing (sent by us) */
        if (from.sll_pkttype == PACKET_OUTGOING) continue;

        total_pkts++;

        /* DEBUG: log first few raw captures to verify AF_PACKET is working */
        if (total_pkts <= 3) {
            log_info("IN[%d] raw capture #%lu: len=%zd ethertype=0x%04x",
                     w->id, total_pkts, n,
                     (uint32_t)((rx_buf[12] << 8) | rx_buf[13]));
        }

        /* ---- FILTER: Outer Eth(14) + Outer IP(20) + Outer UDP(8) + VXLAN(8) = 50 min ---- */
        if ((uint32_t)n < 14 + 20 + 8 + VXLAN_HDR_SIZE) continue;

        /* Check outer Ethertype = IPv4 (0x0800) */
        uint16_t outer_ethertype = ((uint16_t)rx_buf[12] << 8) | rx_buf[13];
        if (outer_ethertype != 0x0800) continue;

        /* Filter: ignore if the source MAC is our own (extra safety against loopback) */
        if (memcmp(rx_buf + 6, fg->local.src_mac, 6) == 0) continue;

        /* Check outer IP protocol = UDP (17) */
        uint8_t outer_ip_proto = rx_buf[14 + 9];
        if (outer_ip_proto != 17) continue;

        /* Get outer IP header length (may have options) */
        int outer_ihl = (rx_buf[14] & 0x0F) * 4;
        if (outer_ihl < 20) continue;
        if ((uint32_t)n < (uint32_t)(14 + outer_ihl + 8 + VXLAN_HDR_SIZE)) continue;

        /* Check outer UDP destination port matches one of our tunnel ports */
        int udp_offset = 14 + outer_ihl;
        uint16_t dst_port = ((uint16_t)rx_buf[udp_offset + 2] << 8) | rx_buf[udp_offset + 3];

        int port_match = 0;
        for (size_t p = 0; p < tunnel_port_count; p++) {
            if (dst_port == tunnel_ports[p]) { port_match = 1; break; }
        }
        if (!port_match) continue;

        filtered++;

        /* DEBUG: log matched VXLAN packets + Interface ID to detect Bridge Duplication */
        if (filtered <= 10) {
            log_info("IN[%d] MATCH #%lu: ifindex=%d dst_port=%u outer_len=%zd ihl=%d",
                     w->id, filtered, from.sll_ifindex, dst_port, n, outer_ihl);
        }

        /* ---- Strip outer headers: Eth(14) + IP(outer_ihl) + UDP(8) ---- */
        int vxlan_offset = 14 + outer_ihl + 8;

        /* Read VXLAN header */
        vxlan_hdr_t *vxhdr = (vxlan_hdr_t *)(rx_buf + vxlan_offset);
        uint16_t pkt_id;
        uint8_t frag_index;
        vxlan_hdr_read_frag(vxhdr, &pkt_id, &frag_index);

        /* Inner data starts after VXLAN header */
        int inner_offset = vxlan_offset + VXLAN_HDR_SIZE;
        uint8_t *inner_data = rx_buf + inner_offset;
        uint32_t inner_len = (uint32_t)(n - inner_offset);

        /* DEBUG: log VXLAN header parse result */
        if (filtered <= 10) {
            log_info("IN[%d] VXLAN: frag=%u pkt_id=%u inner_len=%u vxlan_offset=%d",
                     w->id, frag_index, pkt_id, inner_len, vxlan_offset);
        }

        if (frag_index == VXLAN_FRAG_NONE) {
            /* ---- Unfragmented: inner_data is a complete Ethernet frame ---- */
            if (inner_len < 14) continue;

            uint8_t *ip_data = inner_data + 14;
            int is_ipv4 = ((ip_data[0] >> 4) == 4);
            if (is_ipv4) {
                memcpy(inner_data, cached_eth_ipv4, 14);
                sa.sll_protocol = htons(ETH_P_IP);
            } else {
                memcpy(inner_data, cached_eth_ipv6, 14);
                sa.sll_protocol = htons(ETH_P_IPV6);
            }

            ssize_t tx_rc = sendto(w->tx_fd, inner_data, inner_len, 0,
                   (struct sockaddr *)&sa, sizeof(sa));
                if (pkt_cnt <= 5) {
                    log_info("IN[%d] FWD unfrag #%lu: inner_len=%u tx_rc=%zd to MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                             w->id, pkt_cnt, inner_len, tx_rc,
                             cached_eth_ipv4[0], cached_eth_ipv4[1], cached_eth_ipv4[2],
                             cached_eth_ipv4[3], cached_eth_ipv4[4], cached_eth_ipv4[5]);
                    if (tx_rc < 0) log_error("  -> Error: %s", strerror(errno));
                }
        } else {
            /* ---- Fragmented: store or reassemble ---- */
            if (!fg->frag_tbl) continue;

            uint32_t reassem_len = 0;
            int ret = frag_store_or_reassemble(fg->frag_tbl,
                                               inner_data, inner_len,
                                               pkt_id, frag_index,
                                               reassem_buf, &reassem_len);
            if (ret == 1) {
                /* Reassembled: complete original Ethernet frame */
                if (reassem_len < 14) continue;

                uint8_t *ip_data = reassem_buf + 14;
                int is_ipv4 = ((ip_data[0] >> 4) == 4);
                if (is_ipv4) {
                    memcpy(reassem_buf, cached_eth_ipv4, 14);
                    sa.sll_protocol = htons(ETH_P_IP);
                } else {
                    memcpy(reassem_buf, cached_eth_ipv6, 14);
                    sa.sll_protocol = htons(ETH_P_IPV6);
                }

                ssize_t tx_rc = sendto(w->tx_fd, reassem_buf, reassem_len, 0,
                       (struct sockaddr *)&sa, sizeof(sa));
                if (pkt_cnt <= 5) {
                    log_info("IN[%d] FWD reassembled #%lu: len=%u tx_rc=%zd to MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                             w->id, pkt_cnt, reassem_len, tx_rc,
                             cached_eth_ipv4[0], cached_eth_ipv4[1], cached_eth_ipv4[2],
                             cached_eth_ipv4[3], cached_eth_ipv4[4], cached_eth_ipv4[5]);
                    if (tx_rc < 0) log_error("  -> Error: %s", strerror(errno));
                }
            }
            /* ret == 0: stored fragment, waiting for counterpart */
        }
    }

    free(rx_buf);
    free(reassem_buf);
    close(rx_fd);
    log_info("IN[%d] FINAL: total_raw=%lu filtered_vxlan=%lu forwarded=%lu",
             w->id, total_pkts, filtered, pkt_cnt);
}
