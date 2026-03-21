#define _GNU_SOURCE
#include "userio/afpkt.h"
#include "utils/logger.h"
#include "system/system.h"
#include "system/arp.h"
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

#include <linux/filter.h>
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
#define OUT_BATCH_SIZE 64
#define IN_BATCH_SIZE 32
#define BUSY_WAIT_COUNT 1000

/* BPF Filter for MWAN_ETHERTYPE (0x88B5) and BLOCK PACKET_OUTGOING (Loop prevention) */
static void afpkt_set_mwan_filter(int fd) {
    struct sock_filter code[] = {
        { 0x20, 0, 0, 0xfffff004 }, /* L0: ld pkt_type (SKF_AD_OFF + SKF_AD_PKTTYPE) */
        { 0x15, 3, 0, 0x00000004 }, /* L1: if == PACKET_OUTGOING (4) goto L5 (DROP), else next */
        { 0x28, 0, 0, 0x0000000c }, /* L2: ldH [12] (EtherType) */
        { 0x15, 0, 1, 0x000088b5 }, /* L3: if == 0x88B5 goto L4, else goto L5 */
        { 0x06, 0, 0, 0x0000ffff }, /* L4: ret ALL */
        { 0x06, 0, 0, 0x00000000 }, /* L5: ret 0 */
    };
    struct sock_fprog bpf = {
        .len = (unsigned short)(sizeof(code)/sizeof(code[0])),
        .filter = code,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_warn("Failed to attach BPF filter: %s", strerror(errno));
    }
}

// static void log_hex_dump(const char *label, const uint8_t *data, size_t len) {
//     char buf[512];
//     size_t pos = 0;
//     pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (%zu bytes): ", label, len);
//     for (size_t i = 0; i < len && i < 64; i++) {
//         pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x ", data[i]);
//         if (pos > sizeof(buf) - 10) break;
//     }
//     log_info("%s%s", buf, (len > 64) ? "..." : "");
// }

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

    int ifidx = 0;
    if (ifname) {
        ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            log_error("if_nametoindex(%s) failed", ifname);
            return -1;
        }
    }

    for (int i = 0; i < num_workers; i++)
    {
        afpkt_worker_t *w = &fg->workers[i];
        w->id = i;

        /* 1. RX socket: Use MWAN_ETHERTYPE for Inbound group (2) to filter at kernel level */
        uint16_t proto = (fanout_group_id >= 2) ? MWAN_ETHERTYPE : ETH_P_ALL;
        w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(proto));
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

        /* 6. Apply BPF Filter for Inbound groups (group 2+) */
        if (fanout_group_id >= 2) {
            afpkt_set_mwan_filter(w->rx_fd);
        }

        /* 7. TX socket */
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
        
        /* Initialize health tracking */
        fg->tunnel_alive[i] = 1;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        fg->last_seen_ns[i] = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    /* Open AF_PACKET socket for inbound Ethernet forwarding */
    fg->local_tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fg->local_tx_fd < 0) {
        log_error("Failed to open AF_PACKET TX socket for local_if: %s", strerror(errno));
    } else {
        int sndbuf = 16 * 1024 * 1024;
        setsockopt(fg->local_tx_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
    }

    return 0;
}

/* Open a single TPACKET_V3 RX worker bound to a specific tunnel interface + BPF + TX socket */
int afpkt_single_open_inbound(afpkt_worker_t *w, const char *tunnel_ifname, int worker_id)
{
    memset(w, 0, sizeof(*w));
    w->id = worker_id;
    w->rx_fd = -1;
    w->tx_fd = -1;

    int ifidx = if_nametoindex(tunnel_ifname);
    if (ifidx == 0) {
        log_error("InboundSingle[%d]: if_nametoindex(%s) failed", worker_id, tunnel_ifname);
        return -1;
    }

    /* 1. RX socket: listen ONLY for MWAN_ETHERTYPE */
    w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(MWAN_ETHERTYPE));
    if (w->rx_fd < 0) {
        log_error("InboundSingle[%d]: socket(RX) failed: %s", worker_id, strerror(errno));
        return -1;
    }

    /* 2. TPACKET_V3 */
    int version = TPACKET_V3;
    setsockopt(w->rx_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    int ignore_out = 1;
    setsockopt(w->rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));

    /* 3. Bind STRICTLY to this tunnel interface */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(MWAN_ETHERTYPE),
        .sll_ifindex  = ifidx,
    };
    if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        log_error("InboundSingle[%d]: bind(%s) failed: %s", worker_id, tunnel_ifname, strerror(errno));
        close(w->rx_fd); w->rx_fd = -1;
        return -1;
    }

    /* 4. RX ring */
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = V3_BLOCK_SIZE;
    req.tp_frame_size = V3_FRAME_SIZE;
    req.tp_block_nr   = V3_BLOCK_NR;
    req.tp_frame_nr   = (V3_BLOCK_SIZE * V3_BLOCK_NR) / V3_FRAME_SIZE;
    req.tp_retire_blk_tov = 3;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
        log_error("InboundSingle[%d]: PACKET_RX_RING failed: %s", worker_id, strerror(errno));
        close(w->rx_fd); w->rx_fd = -1;
        return -1;
    }

    size_t ring_sz = (size_t)req.tp_block_size * req.tp_block_nr;
    w->ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED, w->rx_fd, 0);
    if (w->ring == MAP_FAILED) {
        log_error("InboundSingle[%d]: mmap failed: %s", worker_id, strerror(errno));
        w->ring = NULL;
        close(w->rx_fd); w->rx_fd = -1;
        return -1;
    }
    w->ring_size = ring_sz;
    w->block_count = req.tp_block_nr;
    w->current_block = 0;

    /* 5. Attach BPF (redundant safety — socket already filters by protocol) */
    afpkt_set_mwan_filter(w->rx_fd);

    /* 6. TX socket for sending to LAN */
    w->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (w->tx_fd < 0) {
        log_error("InboundSingle[%d]: socket(TX) failed: %s", worker_id, strerror(errno));
        munmap(w->ring, w->ring_size); w->ring = NULL;
        close(w->rx_fd); w->rx_fd = -1;
        return -1;
    }
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(w->tx_fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));

    log_info("InboundSingle[%d]: %s (ifindex=%d) rx_fd=%d tx_fd=%d V3_Blocks=%u",
             worker_id, tunnel_ifname, ifidx, w->rx_fd, w->tx_fd, w->block_count);
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

    if (fg->local_tx_fd >= 0) {
        close(fg->local_tx_fd);
        fg->local_tx_fd = -1;
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

        fg->tunnel_ifindices[i] = ifidx;
        fg->tunnel_fds[i] = -1; // No longer used for sending, using worker->tx_fd
        log_info("Cache outbound: TUNNEL[%zu] %s (ifindex=%d)", i, ifname, ifidx);
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
void afpkt_worker_loop_outbound(afpkt_worker_t *w, afpkt_fanout_t *fg,
                                const app_context_t *ctx, volatile int *running)
{
    unsigned long pkt_cnt = 0;
    unsigned long captured_cnt = 0;
    unsigned long ip_pkts = 0;
    unsigned long syscalls = 0;
    log_info("Worker outbound[%d] started (sendmmsg Batching + Busy Polling)", w->id);

    size_t tunnel_count = ctx->cfg.ne_tunnel_count;
    if (tunnel_count == 0) {
        log_error("Worker outbound[%d]: no ne_tunnels configured!", w->id);
        return;
    }

    /* Batching structures */
    struct mmsghdr msgs[OUT_BATCH_SIZE];
    struct iovec iovs[OUT_BATCH_SIZE][2];
    struct sockaddr_ll addrs[OUT_BATCH_SIZE];
    struct {
        struct ethhdr eth;
        mwan_metadata_t meta;
    } __attribute__((packed)) hdrs[OUT_BATCH_SIZE];

    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < OUT_BATCH_SIZE; i++) {
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
        msgs[i].msg_hdr.msg_iov = iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 2;
        
        addrs[i].sll_family = AF_PACKET;
        addrs[i].sll_halen = 6;
        hdrs[i].eth.h_proto = htons(MWAN_ETHERTYPE);
    }

    int batch_idx = 0;
    int busy_tickets = 0;

    while (*running)
    {
        if (busy_tickets > 0) {
            busy_tickets--;
        } else {
            struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
            if (poll(&pfd, 1, 10) <= 0)
                continue;
        }

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            /* Reset busy tickets if we found a block with data */
            busy_tickets = BUSY_WAIT_COUNT;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                captured_cnt++;

                if (len < 34) goto next_pkt;

                struct ethhdr *eth = (struct ethhdr *)frame;
                uint16_t h_proto = ntohs(eth->h_proto);

                if (h_proto == MWAN_ETHERTYPE) goto next_pkt;
                if (memcmp(eth->h_source, fg->local.src_mac, 6) == 0) goto next_pkt;
                if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6) goto next_pkt;

                ip_pkts++;

                uint32_t hash = calculate_5tuple_hash(frame, len);
                int t_idx = hash % tunnel_count;
                
                /* Failover logic: if selected tunnel is dead, pick next alive one */
                if (!fg->tunnel_alive[t_idx]) {
                    int found = 0;
                    for (size_t k = 1; k < tunnel_count; k++) {
                        int try_idx = (t_idx + k) % tunnel_count;
                        if (fg->tunnel_alive[try_idx]) {
                            t_idx = try_idx;
                            found = 1;
                            break;
                        }
                    }
                    if (!found) goto next_pkt; /* All tunnels dead */
                }
                
                int t_ifidx = fg->tunnel_ifindices[t_idx];

                uint32_t ip_len = len - 14;
                uint8_t *ip_ptr = frame + 14;

                if (frag_need_split(ip_len)) {
                    uint16_t p_id = frag_next_pkt_id();
                    uint32_t half1 = ip_len / 2;
                    uint32_t half2 = ip_len - half1;

                    /* Fragment 1 */
                    struct sockaddr_ll *sa = &addrs[batch_idx];
                    sa->sll_ifindex = t_ifidx;
                    memcpy(sa->sll_addr, eth->h_dest, 6);

                    struct ethhdr *eh = &hdrs[batch_idx].eth;
                    memcpy(eh->h_dest, eth->h_dest, 6);
                    memcpy(eh->h_source, eth->h_source, 6);

                    mwan_metadata_build(&hdrs[batch_idx].meta, p_id, MWAN_FRAG_FIRST, MWAN_TYPE_DATA);
                    iovs[batch_idx][0].iov_base = &hdrs[batch_idx];
                    iovs[batch_idx][0].iov_len  = sizeof(hdrs[0]);
                    iovs[batch_idx][1].iov_base = ip_ptr;
                    iovs[batch_idx][1].iov_len  = half1;
                    batch_idx++;

                    if (batch_idx == OUT_BATCH_SIZE) {
                        sendmmsg(w->tx_fd, msgs, batch_idx, 0);
                        batch_idx = 0;
                        syscalls++;
                    }

                    /* Fragment 2 */
                    sa = &addrs[batch_idx];
                    sa->sll_ifindex = t_ifidx;
                    memcpy(sa->sll_addr, eth->h_dest, 6);

                    eh = &hdrs[batch_idx].eth;
                    memcpy(eh->h_dest, eth->h_dest, 6);
                    memcpy(eh->h_source, eth->h_source, 6);

                    mwan_metadata_build(&hdrs[batch_idx].meta, p_id, MWAN_FRAG_LAST, MWAN_TYPE_DATA);
                    iovs[batch_idx][0].iov_base = &hdrs[batch_idx];
                    iovs[batch_idx][0].iov_len  = sizeof(hdrs[0]);
                    iovs[batch_idx][1].iov_base = ip_ptr + half1;
                    iovs[batch_idx][1].iov_len  = half2;
                    batch_idx++;
                } else {
                    struct sockaddr_ll *sa = &addrs[batch_idx];
                    sa->sll_ifindex = t_ifidx;
                    memcpy(sa->sll_addr, eth->h_dest, 6);

                    struct ethhdr *eh = &hdrs[batch_idx].eth;
                    memcpy(eh->h_dest, eth->h_dest, 6);
                    memcpy(eh->h_source, eth->h_source, 6);

                    mwan_metadata_build(&hdrs[batch_idx].meta, 0, MWAN_FRAG_NONE, MWAN_TYPE_DATA);
                    iovs[batch_idx][0].iov_base = &hdrs[batch_idx];
                    iovs[batch_idx][0].iov_len  = sizeof(hdrs[0]);
                    iovs[batch_idx][1].iov_base = ip_ptr;
                    iovs[batch_idx][1].iov_len  = ip_len;
                    batch_idx++;
                }
                pkt_cnt++;

                if (batch_idx == OUT_BATCH_SIZE) {
                    sendmmsg(w->tx_fd, msgs, batch_idx, 0);
                    batch_idx = 0;
                    syscalls++;
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }

        /* Flush remaining batch */
        if (batch_idx > 0) {
            sendmmsg(w->tx_fd, msgs, batch_idx, 0);
            batch_idx = 0;
            syscalls++;
        }
    }
    log_info("OUT[%d] FINAL: captured=%lu ip_pkts=%lu forwarded=%lu syscalls=%lu",
             w->id, captured_cnt, ip_pkts, pkt_cnt, syscalls);
}


void afpkt_worker_loop_inbound(afpkt_worker_t *w, afpkt_fanout_t *fg,
                                const app_context_t *ctx, const char *listen_ifname, volatile int *running)
{
    (void)listen_ifname;
    (void)ctx;
    unsigned long pkt_cnt = 0;
    unsigned long total_raw = 0;
    unsigned long handled = 0;
    unsigned long syscalls = 0;

    log_info("Worker inbound[%d] started (sendmmsg Batching + Busy Polling)", w->id);

    /* Batching structures */
    struct mmsghdr msgs[IN_BATCH_SIZE];
    struct iovec iovs[IN_BATCH_SIZE][2];
    struct sockaddr_ll addrs[IN_BATCH_SIZE];
    struct ethhdr eth_hdrs[IN_BATCH_SIZE];
    
    /* Pool for reassembled packets (one per batch slot) */
    uint8_t *reassem_pool = malloc(IN_BATCH_SIZE * 4096);
    if (!reassem_pool) return;

    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < IN_BATCH_SIZE; i++) {
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
        msgs[i].msg_hdr.msg_iov = iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 2;
        
        addrs[i].sll_family = AF_PACKET;
        addrs[i].sll_ifindex = fg->local.ifindex;
        addrs[i].sll_halen = 6;
        
        eth_hdrs[i].h_proto = htons(ETH_P_IP);
        memcpy(eth_hdrs[i].h_source, fg->local.src_mac, 6);
    }

    int batch_idx = 0;
    int busy_tickets = 0;

    while (*running)
    {
        if (busy_tickets > 0) {
            busy_tickets--;
        } else {
            struct pollfd pfd = {.fd = w->rx_fd, .events = POLLIN};
            if (poll(&pfd, 1, 10) <= 0)
                continue;
        }

        while (*running)
        {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break;

            busy_tickets = BUSY_WAIT_COUNT;

            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            for (int i = 0; i < num_pkts; i++)
            {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;

                total_raw++;

                if (len < (14 + MWAN_METADATA_SIZE)) goto next_pkt;
                
                uint16_t pkt_id;
                uint8_t frag_index, type;
                if (mwan_metadata_read(frame + 14, &pkt_id, &frag_index, &type) != 0) goto next_pkt;

                /* Always update health status for ANY valid MWAN packet received on this tunnel */
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                fg->last_seen_ns[w->id] = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
                fg->tunnel_alive[w->id] = 1;

                /* Handle Heartbeat type-specific logic */
                if (type == MWAN_TYPE_HEARTBEAT) {
                    /* If it's a request, send back a response */
                    if (pkt_id == HEARTBEAT_REQ) {
                        mwan_metadata_t res;
                        mwan_metadata_build(&res, HEARTBEAT_RES, MWAN_FRAG_NONE, MWAN_TYPE_HEARTBEAT);
                        
                        uint8_t padding[42] = {0};
                        struct iovec hiov[3];
                        hiov[0].iov_base = frame;     /* reuse Ethernet header */
                        hiov[0].iov_len  = 14;
                        hiov[1].iov_base = &res;
                        hiov[1].iov_len  = sizeof(res);
                        hiov[2].iov_base = padding;
                        hiov[2].iov_len  = sizeof(padding);

                        struct sockaddr_ll sa = {
                            .sll_family = AF_PACKET,
                            .sll_ifindex = fg->tunnel_ifindices[w->id],
                            .sll_halen = 6,
                        };
                        struct ethhdr *eth = (struct ethhdr *)frame;
                        memcpy(sa.sll_addr, eth->h_source, 6); /* Send back to whoever asked */

                        struct msghdr m = {
                            .msg_name = &sa, .msg_namelen = sizeof(sa),
                            .msg_iov = hiov, .msg_iovlen = 3,
                        };
                        sendmsg(w->tx_fd, &m, 0);
                    }
                    goto next_pkt;
                }

                uint8_t *ip_ptr = NULL;
                uint32_t ip_len = 0;

                if (frag_index == MWAN_FRAG_NONE) {
                    ip_ptr = frame + 14 + MWAN_METADATA_SIZE;
                    ip_len = len - (14 + MWAN_METADATA_SIZE);
                } else {
                    uint32_t rlen = 0;
                    uint8_t *tmp_buf = reassem_pool + (batch_idx * 4096);
                    int ret = frag_store_or_reassemble(fg->frag_tbl,
                                                       frame + 14 + MWAN_METADATA_SIZE,
                                                       (uint32_t)(len - (14 + MWAN_METADATA_SIZE)),
                                                       pkt_id, frag_index,
                                                       tmp_buf, &rlen);
                    if (ret == 1) {
                        ip_ptr = tmp_buf;
                        ip_len = rlen;
                    } else {
                        goto next_pkt;
                    }
                }

                if (ip_ptr && ip_len > 0) {
                    uint8_t ver = (ip_ptr[0] >> 4);
                    if (ver == 4) {
                        struct iphdr *iph = (struct iphdr *)ip_ptr;
                        struct sockaddr_ll *sll = &addrs[batch_idx];
                        struct ethhdr *eth = &eth_hdrs[batch_idx];
                        
                        uint8_t dst_mac[6];
                        if (arp_cache_lookup(iph->daddr, dst_mac) == 0) {
                            memcpy(eth->h_dest, dst_mac, 6);
                            memcpy(sll->sll_addr, dst_mac, 6);
                            
                            iovs[batch_idx][0].iov_base = eth;
                            iovs[batch_idx][0].iov_len  = sizeof(struct ethhdr);
                            iovs[batch_idx][1].iov_base = ip_ptr;
                            iovs[batch_idx][1].iov_len  = ip_len;
                            batch_idx++;
                            pkt_cnt++;
                        } else {
                            /* Fallback to drop */
                            log_debug("Worker inbound[%d]: No ARP entry for IP %x, dropping", w->id, ntohl(iph->daddr));
                        }
                    }
                }
                handled++;

                if (batch_idx == IN_BATCH_SIZE) {
                    sendmmsg(fg->local_tx_fd, msgs, batch_idx, 0);
                    batch_idx = 0;
                    syscalls++;
                }

            next_pkt:
                ppd = (struct tpacket3_hdr *)((char *)ppd + ppd->tp_next_offset);
            }

            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }

        if (batch_idx > 0) {
            sendmmsg(fg->local_tx_fd, msgs, batch_idx, 0);
            batch_idx = 0;
            syscalls++;
        }
    }

    free(reassem_pool);
    log_info("IN[%d] FINAL: tunnel_raw=%lu handled=%lu forwarded=%lu syscalls=%lu",
             w->id, total_raw, handled, pkt_cnt, syscalls);
}

void afpkt_fanout_check_health(afpkt_fanout_t *fg) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    for (size_t i = 0; i < fg->tunnel_count; i++) {
        if (fg->tunnel_alive[i] && (now - fg->last_seen_ns[i]) > 3000000000ULL) {
            fg->tunnel_alive[i] = 0;
            log_warn("Tunnel %zu marked DEAD (timeout)", i);
        }
    }
}

void afpkt_fanout_send_heartbeats(afpkt_fanout_t *fg) {
    mwan_metadata_t req;
    mwan_metadata_build(&req, HEARTBEAT_REQ, MWAN_FRAG_NONE, MWAN_TYPE_HEARTBEAT);

    for (size_t i = 0; i < fg->tunnel_count; i++) {
        /* We need a valid Ethernet header to satisfy the receiver's offset (14) */
        struct {
            struct ethhdr eth;
            mwan_metadata_t meta;
            uint8_t padding[42]; /* Ensure 64-byte minimum Ethernet frame size */
        } __attribute__((packed)) hb_pkt;
        
        memset(&hb_pkt, 0, sizeof(hb_pkt));
        
        /* Use Broadcast MAC for heartbeats to avoid dropping by simple switches/NICs */
        memset(hb_pkt.eth.h_dest, 0xFF, 6);
        memcpy(hb_pkt.eth.h_source, fg->local.src_mac, 6);
        hb_pkt.eth.h_proto = htons(MWAN_ETHERTYPE);
        hb_pkt.meta = req;

        struct sockaddr_ll sa = {
            .sll_family = AF_PACKET,
            .sll_ifindex = fg->tunnel_ifindices[i],
            .sll_halen = 6,
        };
        memset(sa.sll_addr, 0xFF, 6); /* Broadcast dest at link layer */
        
        /* Use the first worker's TX socket to send probes */
        sendto(fg->workers[0].tx_fd, &hb_pkt, sizeof(hb_pkt), 0, (struct sockaddr *)&sa, sizeof(sa));
    }
}
