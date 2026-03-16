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

static void log_hex_dump(const char *label, const uint8_t *data, size_t len) {
    char buf[512];
    size_t pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 64; i++) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x ", data[i]);
        if (pos > sizeof(buf) - 10) break;
    }
    log_info("%s%s", buf, (len > 64) ? "..." : "");
}

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
    for (size_t i = 0; i < fg->tunnel_count; i++) {
        if (fg->tunnel_fds[i] >= 0) {
            close(fg->tunnel_fds[i]);
            fg->tunnel_fds[i] = -1;
        }
    }

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
    fg->tunnel_count = ctx->cfg.ne_tunnel_count;
    for (size_t i = 0; i < fg->tunnel_count && i < MAX_NE_TUNNELS; i++)
    {
        const char *ifname = ctx->cfg.ne_tunnels[i].ifname;
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            log_error("Cache outbound: bridge interface %s not found", ifname);
            fg->tunnel_fds[i] = -1;
            continue;
        }
        fg->tunnel_ifindices[i] = ifidx;

        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
            log_error("Cache outbound: Failed to create AF_PACKET socket for %s: %s", ifname, strerror(errno));
            fg->tunnel_fds[i] = -1;
            continue;
        }
        
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex = ifidx,
        };
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            log_error("Cache outbound: bind to %s failed: %s", ifname, strerror(errno));
            close(fd);
            fg->tunnel_fds[i] = -1;
            continue;
        }

        int sndbuf = 16 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
        fg->tunnel_fds[i] = fd;

        log_info("Cache outbound: TUNNEL[%zu] %s (ifindex=%d, fd=%d)", i, ifname, ifidx, fd);
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
    log_info("Worker outbound[%d] started (VXLAN UDP Encapsulation - ZeroCopy)", w->id);

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0) {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        return;
    }

    /* Pre-prepare header template and msg structures (Outside Loop) */
    struct {
        struct ethhdr eth;
        mwan_metadata_t meta;
    } __attribute__((packed)) m_hdr;
    
    m_hdr.eth.h_proto = htons(MWAN_ETHERTYPE);

    struct iovec iov[2];
    struct msghdr msg;
    struct sockaddr_ll sa;
    
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_halen = 6;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

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

                /* Filter: Needs (14) Eth + (20) IP minimum */
                if (len < 34) goto next_pkt;

                struct ethhdr *eth = (struct ethhdr *)frame;
                uint16_t h_proto = ntohs(eth->h_proto);

                /* Skip internal/loopback traffic and identify purely IP traffic */
                if (h_proto == MWAN_ETHERTYPE) goto next_pkt;
                if (memcmp(eth->h_source, fg->local.src_mac, 6) == 0) goto next_pkt;
                if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6) goto next_pkt;

                ip_pkts++;

                /* Load balance across tunnels */
                uint32_t hash = calculate_5tuple_hash(frame, len);
                int t_idx = hash % tunnel_count;
                int tunnel_fd = fg->tunnel_fds[t_idx];
                if (tunnel_fd < 0) goto next_pkt;

                /* Prepare target tunnel address */
                sa.sll_ifindex = fg->tunnel_ifindices[t_idx];
                memcpy(sa.sll_addr, eth->h_dest, 6);

                /* Prepare shared Ethernet header fields */
                memcpy(m_hdr.eth.h_dest, eth->h_dest, 6);
                memcpy(m_hdr.eth.h_source, eth->h_source, 6);

                uint32_t ip_len = len - 14;
                uint8_t *ip_ptr = frame + 14;

                if (frag_need_split(ip_len)) {
                    uint16_t p_id = frag_next_pkt_id();
                    uint32_t half1 = ip_len / 2;
                    uint32_t half2 = ip_len - half1;

                    /* Fragment 1: Zero-Copy IP Payload */
                    mwan_metadata_build(&m_hdr.meta, p_id, MWAN_FRAG_FIRST);
                    iov[0].iov_base = &m_hdr;
                    iov[0].iov_len  = sizeof(m_hdr);
                    iov[1].iov_base = ip_ptr;
                    iov[1].iov_len  = half1;
                    sendmsg(tunnel_fd, &msg, 0);

                    /* Fragment 2: Zero-Copy IP Payload */
                    mwan_metadata_build(&m_hdr.meta, p_id, MWAN_FRAG_LAST);
                    iov[1].iov_base = ip_ptr + half1;
                    iov[1].iov_len  = half2;
                    sendmsg(tunnel_fd, &msg, 0);
                } else {
                    /* Non-fragmented: Wrap with MWAN Metadata(NONE) */
                    mwan_metadata_build(&m_hdr.meta, 0, MWAN_FRAG_NONE);
                    iov[0].iov_base = &m_hdr;
                    iov[0].iov_len  = sizeof(m_hdr);
                    iov[1].iov_base = ip_ptr;
                    iov[1].iov_len  = ip_len;
                    sendmsg(tunnel_fd, &msg, 0);
                }
                pkt_cnt++;

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }
    }
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
                                const app_context_t *ctx, const char *listen_ifname, volatile int *running)
{
    (void)listen_ifname;
    unsigned long pkt_cnt = 0;
    unsigned long total_raw = 0;
    unsigned long handled = 0;

    log_info("Worker inbound[%d] started (ZeroCopy Forwarding)", w->id);

    int rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx_fd < 0) {
        log_error("Worker inbound[%d]: socket(RX) failed: %s", w->id, strerror(errno));
        return;
    }
    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(rx_fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf));

    /* Pre-prepare LAN Ethernet header template (Outside Loop) */
    struct ethhdr lan_eth;
    memcpy(lan_eth.h_source, fg->local.src_mac, 6);
    memcpy(lan_eth.h_dest, ctx->cfg.lan.dst_mac, 6);

    uint8_t *rx_buf = malloc(4096);
    uint8_t *reassem_buf = malloc(4096);
    if (!rx_buf || !reassem_buf) {
        log_error("Worker inbound[%d]: malloc failed", w->id);
        if (rx_buf) free(rx_buf);
        if (reassem_buf) free(reassem_buf);
        close(rx_fd); return;
    }

    struct iovec iov[2];
    struct msghdr msg;
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = fg->local.ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, ctx->cfg.lan.dst_mac, 6);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    struct pollfd pfd = {.fd = rx_fd, .events = POLLIN};

    while (*running)
    {
        if (poll(&pfd, 1, 100) <= 0) continue;

        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(rx_fd, rx_buf, 4096, 0, (struct sockaddr *)&from, &fromlen);
        if (n <= 0) continue;
        if (from.sll_pkttype == PACKET_OUTGOING) continue;

        /* Filter: Only traffic from our tunnel interfaces */
        int is_tunnel = 0;
        for (size_t i = 0; i < fg->tunnel_count; i++) {
            if (from.sll_ifindex == fg->tunnel_ifindices[i]) {
                is_tunnel = 1; break;
            }
        }
        if (!is_tunnel) continue;

        total_raw++;
        struct ethhdr *eth = (struct ethhdr *)rx_buf;
        
        /* Must be our custom EtherType for identification */
        if (ntohs(eth->h_proto) != MWAN_ETHERTYPE) continue;
        if (n < (ssize_t)(14 + MWAN_METADATA_SIZE)) continue;

        uint16_t pkt_id;
        uint8_t frag_index;
        if (mwan_metadata_read(rx_buf + 14, &pkt_id, &frag_index) != 0) continue;

        uint8_t *ip_data = NULL;
        uint32_t ip_len = 0;

        if (frag_index == MWAN_FRAG_NONE) {
            ip_data = rx_buf + 14 + MWAN_METADATA_SIZE;
            ip_len = (uint32_t)(n - (14 + MWAN_METADATA_SIZE));
        } else {
            /* Reassembly case: involves mandatory copy but optimized storage */
            uint32_t rlen = 0;
            int ret = frag_store_or_reassemble(fg->frag_tbl,
                                               rx_buf + 14 + MWAN_METADATA_SIZE,
                                               (uint32_t)(n - (14 + MWAN_METADATA_SIZE)),
                                               pkt_id, frag_index,
                                               reassem_buf, &rlen);
            if (ret == 1) {
                ip_data = reassem_buf;
                ip_len = rlen;
            } else {
                continue; /* Stored or error */
            }
        }

        if (ip_data && ip_len > 0) {
            /* Detect Protocol (IPv4/v6) based on IP Header Version byte */
            uint8_t ver = (ip_data[0] >> 4);
            if (ver == 4) lan_eth.h_proto = htons(ETH_P_IP);
            else if (ver == 6) lan_eth.h_proto = htons(ETH_P_IPV6);
            else continue;

            /* Forward to LAN via Zero-Copy (Template Header + Receive/Reassembly Buffer) */
            iov[0].iov_base = &lan_eth;
            iov[0].iov_len  = 14;
            iov[1].iov_base = ip_data;
            iov[1].iov_len  = ip_len;
            sendmsg(w->tx_fd, &msg, 0);
            pkt_cnt++;
        }
        handled++;
    }

    free(rx_buf);
    free(reassem_buf);
    close(rx_fd);
    log_info("IN[%d] FINAL: tunnel_raw=%lu handled=%lu forwarded=%lu",
             w->id, total_raw, handled, pkt_cnt);
}