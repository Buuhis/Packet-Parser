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

/* TPACKET_V3 constants */
#define V3_BLOCK_SIZE   (1 << 21) /* 2MB Blocks */
#define V3_BLOCK_NR     64        /* 64 blocks = 128MB Ring */
#define V3_FRAME_SIZE   2048      /* Max frame size (not physically strictly enforced in V3 blocks but used in req) */

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

        /* 2. Set TPACKET_V3 version (MUST be done before ring setup) */
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
        req.tp_retire_blk_tov = 10; /* ms timeout to retire block even if not full */
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

        /* 5. PACKET_FANOUT — kernel distributes packets round-robin (Load Balancing) */
        /*    This ensures single-flow traffic is distributed to ALL workers */
        int fanout_arg = (fanout_group_id & 0xFFFF)
                       | (PACKET_FANOUT_LB << 16);
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

        log_info("Fanout[%d] worker %d: rx_fd=%d tx_fd=%d V3_Blocks=%u",
                 fanout_group_id, i, w->rx_fd, w->tx_fd, w->block_count);
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
    log_info("Worker outbound[%d] started (V3 Polling)", w->id);

    struct mmsghdr msgs[64];
    struct iovec iovs[64];
    struct sockaddr_ll sas[64];
    /* frame_ptrs not needed */

    while (*running) {
        /* 1. Poll for blocks */
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 0) == 0) {
            continue;
        }

        /* 2. Process ALL ready blocks */
        while (*running) {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break; /* Not ready */

            /* 3. Walk packets inside block */
            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd;
            
            ppd = (struct tpacket3_hdr *) ((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            int batch_cnt = 0;
            for (int i = 0; i < num_pkts; i++) {
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen;
                struct ethhdr *eth = (struct ethhdr *)frame;
                
                /* --- Logic Outbound --- */
                
                /* Round-robin WAN selection for simplicity in this optimization phase */
                /* For production, consider hashing flow (ppd->hv1.tp_rxhash) */
                int selected_wan = (pkt_cnt + i) % ctx->cfg.wan_count;

                if (fg->wans[selected_wan].valid) {
                     int is_valid = 0;
                     /* Manual unrolled check for speed */
                     if (ctx->cfg.wans[selected_wan].dst_mac[0] | ctx->cfg.wans[selected_wan].dst_mac[1] |
                         ctx->cfg.wans[selected_wan].dst_mac[2] | ctx->cfg.wans[selected_wan].dst_mac[3] |
                         ctx->cfg.wans[selected_wan].dst_mac[4] | ctx->cfg.wans[selected_wan].dst_mac[5]) {
                         is_valid = 1;
                     }

                     if (is_valid) {
                        /* Rewrite MAC */
                        memcpy(eth->h_source, fg->wans[selected_wan].src_mac, 6);
                        memcpy(eth->h_dest, ctx->cfg.wans[selected_wan].dst_mac, 6);

                        /* Add to batch */
                        iovs[batch_cnt].iov_base = frame;
                        iovs[batch_cnt].iov_len  = len;

                        memset(&sas[batch_cnt], 0, sizeof(struct sockaddr_ll));
                        sas[batch_cnt].sll_family   = AF_PACKET;
                        sas[batch_cnt].sll_protocol = htons(ETH_P_ALL);
                        sas[batch_cnt].sll_ifindex  = fg->wans[selected_wan].ifindex;
                        sas[batch_cnt].sll_halen    = 6;
                        memcpy(sas[batch_cnt].sll_addr, eth->h_dest, 6);

                        memset(&msgs[batch_cnt], 0, sizeof(struct mmsghdr));
                        msgs[batch_cnt].msg_hdr.msg_name    = &sas[batch_cnt];
                        msgs[batch_cnt].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                        msgs[batch_cnt].msg_hdr.msg_iov     = &iovs[batch_cnt];
                        msgs[batch_cnt].msg_hdr.msg_iovlen  = 1;
                        
                        batch_cnt++;
                     }
                }

                if (batch_cnt == 64) {
                    int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                    if (n > 0) pkt_cnt += n;
                    batch_cnt = 0;
                }
                
                ppd = (struct tpacket3_hdr *) ((char *)ppd + ppd->tp_next_offset);
            }
            
            if (batch_cnt > 0) {
                 int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                 if (n > 0) pkt_cnt += n;
            }

            /* 4. Release Block */
            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            w->current_block = (w->current_block + 1) % w->block_count;
        }

        if (pkt_cnt % 100000 == 0 && pkt_cnt > 0) {
             // log_info("Worker outbound[%d] pkt=%lu", w->id, pkt_cnt);
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
    log_info("Worker inbound[%d] started (V3 Polling)", w->id);

    struct mmsghdr msgs[64];
    struct iovec iovs[64];
    struct sockaddr_ll sas[64];
    /* frame_ptrs array isn't needed for V3 walk, we use pointers directly */

    while (*running) {
        /* 1. Poll (busy-wait or sleep) until a block is ready */
        /*    Since we enabled busy_poll sysctl and setsockopt, poll() will spin in kernel first */
        struct pollfd pfd = { .fd = w->rx_fd, .events = POLLIN };
        if (poll(&pfd, 1, 0) == 0) {
           /* No blocks ready, loop again. 
              Maybe add cpu_relax() or tight loop optimization if needed. */
           continue; 
        }

        /* 2. Process ALL ready blocks */
        while (*running) {
            struct tpacket_block_desc *bd = (struct tpacket_block_desc *)
                ((char *)w->ring + (w->current_block * V3_BLOCK_SIZE));

            if ((bd->hdr.bh1.block_status & TP_STATUS_USER) == 0)
                break; /* Current block is owned by kernel */

            /* 3. Walk packets inside the block */
            int num_pkts = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ppd;
            
            /* First packet is at offset_to_first_pkt */
            ppd = (struct tpacket3_hdr *) ((char *)bd + bd->hdr.bh1.offset_to_first_pkt);

            int batch_cnt = 0;
            for (int i = 0; i < num_pkts; i++) {
                /* Packet payload pointer */
                unsigned char *frame = (unsigned char *)ppd + ppd->tp_mac;
                unsigned int len = ppd->tp_snaplen; 
                struct ethhdr *eth = (struct ethhdr *)frame;
                
                /* --- Logic Inbound --- */

                if (fg->local.valid) {
                    /* Only process if valid, otherwise drop/skip */
                    int valid_dst = 0;
                    if (ctx->cfg.lan.dst_mac[0] | ctx->cfg.lan.dst_mac[1] | 
                        ctx->cfg.lan.dst_mac[2] | ctx->cfg.lan.dst_mac[3] |
                        ctx->cfg.lan.dst_mac[4] | ctx->cfg.lan.dst_mac[5]) {
                        valid_dst = 1;
                    }

                    if (valid_dst) {
                         /* Rewrite L2 */
                        memcpy(eth->h_dest, ctx->cfg.lan.dst_mac, 6);
                        memcpy(eth->h_source, fg->local.src_mac, 6);

                        /* Add to batch */
                        iovs[batch_cnt].iov_base = frame;
                        iovs[batch_cnt].iov_len  = len;

                        memset(&sas[batch_cnt], 0, sizeof(struct sockaddr_ll));
                        sas[batch_cnt].sll_family   = AF_PACKET;
                        sas[batch_cnt].sll_protocol = htons(ETH_P_ALL);
                        sas[batch_cnt].sll_ifindex  = fg->local.ifindex;
                        sas[batch_cnt].sll_halen    = 6;
                        memcpy(sas[batch_cnt].sll_addr, ctx->cfg.lan.dst_mac, 6);

                        memset(&msgs[batch_cnt], 0, sizeof(struct mmsghdr));
                        msgs[batch_cnt].msg_hdr.msg_name    = &sas[batch_cnt];
                        msgs[batch_cnt].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
                        msgs[batch_cnt].msg_hdr.msg_iov     = &iovs[batch_cnt];
                        msgs[batch_cnt].msg_hdr.msg_iovlen  = 1;
                        
                        batch_cnt++;
                    }
                }
                
                /* Flush batch if full */
                if (batch_cnt == 64) {
                    int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                    if (n > 0) pkt_cnt += n;
                    batch_cnt = 0;
                }

                /* Move to next packet in block */
                ppd = (struct tpacket3_hdr *) ((char *)ppd + ppd->tp_next_offset);
            }

            /* Flush remaining packets in block */
            if (batch_cnt > 0) {
                 int n = sendmmsg(w->tx_fd, msgs, batch_cnt, 0);
                 if (n > 0) pkt_cnt += n;
            }

            /* 4. Release Block back to Kernel */
            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            
            /* Move to next block ring index */
            w->current_block = (w->current_block + 1) % w->block_count;
        }
        
        if (pkt_cnt % 100000 == 0 && pkt_cnt > 0) {
             // log_info("Worker inbound[%d] pkt=%lu", w->id, pkt_cnt);
        }
    }
    log_info("Worker inbound[%d] stopped, pkt_cnt=%lu", w->id, pkt_cnt);
}

