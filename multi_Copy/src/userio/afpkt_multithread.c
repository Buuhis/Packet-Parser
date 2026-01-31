#define _GNU_SOURCE
#include "userio/afpkt.h"
#include "utils/logger.h"
#include "system/system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

/* ============================================================
 * MULTI-THREADED PACKET FORWARDING với PACKET_FANOUT
 * ============================================================
 * 
 * Kiến trúc:
 * 
 * 1. PACKET_FANOUT: Kernel tự động phân tán packets qua N threads
 *    dựa trên hash (src/dst IP, port) → Tận dụng hardware RSS
 * 
 * 2. Per-thread TX socket: Mỗi worker có socket riêng
 *    → Tránh lock contention khi sendto()
 * 
 * 3. Batch processing: Gom nhiều packets trước khi send
 *    → Giảm system call overhead
 * 
 * 4. CPU affinity: Pin threads vào cores cụ thể
 *    → Tăng cache locality
 * 
 * ============================================================ */

/* ---- Configuration ---- */
#define NUM_WORKER_THREADS  10

#define RX_BLOCK_SIZE   (1 << 22)   /* 4MB */
#define RX_FRAME_SIZE   4096
#define RX_BLOCK_NR     256

#define SOCKET_RCVBUF   (128 * 1024 * 1024)
#define SOCKET_SNDBUF   (128 * 1024 * 1024)

#define BATCH_SIZE      32  /* Process up to 32 packets before sending */

/* ---- Per-worker context ---- */
typedef struct {
    int worker_id;
    int rx_fd;          /* RX socket (shared FANOUT group) */
    int tx_fd;          /* TX socket (per-worker, no contention!) */
    void *ring;
    size_t ring_size;
    unsigned int frame_nr;
    unsigned int frame_idx;
    
    /* Statistics */
    unsigned long rx_packets;
    unsigned long tx_packets;
    unsigned long tx_errors;
    
    /* Cached interface info */
    struct {
        int ifindex;
        unsigned char src_mac[6];
        unsigned char dst_mac[6];
        int valid;
    } target;
    
    pthread_t thread;
    volatile int running;
} worker_ctx_t;

/* ---- Global state ---- */
static struct {
    worker_ctx_t workers[NUM_WORKER_THREADS];
    int num_workers;
    const app_context_t *app_ctx;
    const char *ifname;
    int fanout_group_id;
    int is_inbound;  /* 0 = outbound, 1 = inbound */
} g_state;

/* ============================================================
 * Helper functions
 * ============================================================ */

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
    
    return 0;
}

static int setup_packet_fanout(int fd, int group_id, int worker_id)
{
    /* PACKET_FANOUT_HASH: Kernel phân tán packets dựa trên hash
     * → Packets của cùng 1 flow luôn đi vào cùng 1 worker
     * → Tránh reordering, tăng cache locality */
    
    int fanout_arg = (group_id & 0xffff) | (PACKET_FANOUT_HASH << 16);
    
    if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) != 0) {
        log_error("Worker %d: PACKET_FANOUT failed: %s", worker_id, strerror(errno));
        return -1;
    }
    
    log_info("Worker %d: Joined FANOUT group %d", worker_id, group_id);
    return 0;
}

static int set_cpu_affinity(int worker_id)
{
    /* Pin thread vào CPU core cụ thể
     * → Giảm context switch, tăng cache hit rate */
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        log_error("Worker %d: Failed to set CPU affinity: %s", 
                  worker_id, strerror(errno));
        return -1;
    }
    
    log_info("Worker %d: Pinned to CPU %d", 
             worker_id, worker_id % sysconf(_SC_NPROCESSORS_ONLN));
    return 0;
}

/* ============================================================
 * Worker thread - Packet processing
 * ============================================================ */

static void *worker_thread(void *arg)
{
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    
    log_info("Worker %d: Started", ctx->worker_id);
    
    /* Set CPU affinity */
    set_cpu_affinity(ctx->worker_id);
    
    struct pollfd pfd = {
        .fd = ctx->rx_fd,
        .events = POLLIN,
    };
    
    /* Batch buffer để gom packets trước khi send */
    struct {
        unsigned char *frame;
        unsigned int len;
        struct sockaddr_ll sll;
    } batch[BATCH_SIZE];
    int batch_count = 0;
    
    while (ctx->running) {
        /* Poll với timeout ngắn */
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0)
            continue;
        
        /* Process packets từ RX ring */
        while (1) {
            struct tpacket_hdr *hdr =
                (struct tpacket_hdr *)((char *)ctx->ring + 
                                       (ctx->frame_idx * RX_FRAME_SIZE));
            
            if (!(hdr->tp_status & TP_STATUS_USER))
                break;  /* No more packets */
            
            ctx->rx_packets++;
            
            /* Get frame */
            unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
            unsigned int len = hdr->tp_len;
            struct ethhdr *eth = (struct ethhdr *)frame;
            
            /* Rewrite MAC addresses (cached) */
            if (ctx->target.valid) {
                memcpy(eth->h_source, ctx->target.src_mac, 6);
                memcpy(eth->h_dest, ctx->target.dst_mac, 6);
                
                /* Add to batch */
                batch[batch_count].frame = frame;
                batch[batch_count].len = len;
                batch[batch_count].sll.sll_family = AF_PACKET;
                batch[batch_count].sll.sll_protocol = htons(ETH_P_ALL);
                batch[batch_count].sll.sll_ifindex = ctx->target.ifindex;
                batch[batch_count].sll.sll_halen = 6;
                memcpy(batch[batch_count].sll.sll_addr, eth->h_dest, 6);
                
                batch_count++;
            } else {
                ctx->tx_errors++;
            }
            
            /* Release frame back to kernel */
            hdr->tp_status = TP_STATUS_KERNEL;
            ctx->frame_idx = (ctx->frame_idx + 1) % ctx->frame_nr;
            
            /* Send batch khi đủ BATCH_SIZE hoặc hết packets */
            if (batch_count >= BATCH_SIZE) {
                /* Send all packets in batch
                 * NOTE: Mỗi worker có TX socket riêng → NO LOCK CONTENTION! */
                for (int i = 0; i < batch_count; i++) {
                    ssize_t n = sendto(ctx->tx_fd, 
                                      batch[i].frame, 
                                      batch[i].len, 
                                      0,
                                      (struct sockaddr *)&batch[i].sll, 
                                      sizeof(batch[i].sll));
                    if (n < 0) {
                        ctx->tx_errors++;
                    } else {
                        ctx->tx_packets++;
                    }
                }
                batch_count = 0;
            }
        }
        
        /* Send remaining packets in batch */
        if (batch_count > 0) {
            for (int i = 0; i < batch_count; i++) {
                ssize_t n = sendto(ctx->tx_fd, 
                                  batch[i].frame, 
                                  batch[i].len, 
                                  0,
                                  (struct sockaddr *)&batch[i].sll, 
                                  sizeof(batch[i].sll));
                if (n < 0) {
                    ctx->tx_errors++;
                } else {
                    ctx->tx_packets++;
                }
            }
            batch_count = 0;
        }
    }
    
    log_info("Worker %d: Stopped (rx=%lu, tx=%lu, errors=%lu, loss=%.2f%%)",
             ctx->worker_id, ctx->rx_packets, ctx->tx_packets, ctx->tx_errors,
             ctx->rx_packets > 0 ? (ctx->tx_errors * 100.0) / ctx->rx_packets : 0.0);
    
    return NULL;
}

/* ============================================================
 * Public API
 * ============================================================ */

int afpkt_multithread_init(const char *ifname, 
                           const app_context_t *app_ctx,
                           int is_inbound)
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.app_ctx = app_ctx;
    g_state.ifname = ifname;
    g_state.num_workers = NUM_WORKER_THREADS;
    g_state.fanout_group_id = getpid() & 0xffff;
    g_state.is_inbound = is_inbound;
    
    log_info("Initializing multi-threaded AF_PACKET (%s) on %s with %d workers",
             is_inbound ? "INBOUND" : "OUTBOUND", ifname, NUM_WORKER_THREADS);
    
    /* Get interface index */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }
    
    /* Prepare target interface info (cache) */
    const char *target_ifname;
    unsigned char target_src_mac[6];
    unsigned char target_dst_mac[6];
    int target_ifindex;
    
    if (is_inbound) {
        /* INBOUND: WAN → LOCAL */
        target_ifname = app_ctx->cfg.local_if;
        target_ifindex = if_nametoindex(target_ifname);
        
        if (system_get_if_hwaddr(target_ifname, target_src_mac) != 0) {
            log_error("Failed to get MAC for LOCAL %s", target_ifname);
            return -1;
        }
        memcpy(target_dst_mac, app_ctx->cfg.lan.dst_mac, 6);
    } else {
        /* OUTBOUND: LOCAL → WAN */
        target_ifname = app_ctx->cfg.wans[1].ifname;  /* WAN[1] */
        target_ifindex = if_nametoindex(target_ifname);
        
        if (system_get_if_hwaddr(target_ifname, target_src_mac) != 0) {
            log_error("Failed to get MAC for WAN %s", target_ifname);
            return -1;
        }
        memcpy(target_dst_mac, app_ctx->cfg.wans[1].dst_mac, 6);
    }
    
    /* Create worker threads */
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        worker_ctx_t *w = &g_state.workers[i];
        w->worker_id = i;
        w->running = 1;
        
        /* Cache target info */
        w->target.ifindex = target_ifindex;
        memcpy(w->target.src_mac, target_src_mac, 6);
        memcpy(w->target.dst_mac, target_dst_mac, 6);
        w->target.valid = 1;
        
        /* Create RX socket */
        w->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->rx_fd < 0) {
            log_error("Worker %d: socket() failed: %s", i, strerror(errno));
            goto cleanup;
        }
        
        /* Set socket buffers */
        if (set_socket_buffers(w->rx_fd) != 0) {
            close(w->rx_fd);
            goto cleanup;
        }
        
        /* Bind to interface */
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex = ifindex,
        };
        
        if (bind(w->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            log_error("Worker %d: bind() failed: %s", i, strerror(errno));
            close(w->rx_fd);
            goto cleanup;
        }
        
        /* Setup PACKET_FANOUT - KEY OPTIMIZATION! */
        if (setup_packet_fanout(w->rx_fd, g_state.fanout_group_id, i) != 0) {
            close(w->rx_fd);
            goto cleanup;
        }
        
        /* Setup RX ring */
        struct tpacket_req req = {
            .tp_block_size = RX_BLOCK_SIZE,
            .tp_frame_size = RX_FRAME_SIZE,
            .tp_block_nr = RX_BLOCK_NR,
            .tp_frame_nr = ((unsigned long)RX_BLOCK_SIZE * RX_BLOCK_NR) / RX_FRAME_SIZE,
        };
        
        if (setsockopt(w->rx_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
            log_error("Worker %d: PACKET_RX_RING failed: %s", i, strerror(errno));
            close(w->rx_fd);
            goto cleanup;
        }
        
        /* mmap RX ring */
        size_t ring_sz = req.tp_block_size * req.tp_block_nr;
        void *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED, w->rx_fd, 0);
        if (ring == MAP_FAILED) {
            log_error("Worker %d: mmap() failed: %s", i, strerror(errno));
            close(w->rx_fd);
            goto cleanup;
        }
        
        w->ring = ring;
        w->ring_size = ring_sz;
        w->frame_nr = req.tp_frame_nr;
        w->frame_idx = 0;
        
        /* Create TX socket (per-worker!) */
        w->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (w->tx_fd < 0) {
            log_error("Worker %d: TX socket() failed: %s", i, strerror(errno));
            munmap(ring, ring_sz);
            close(w->rx_fd);
            goto cleanup;
        }
        
        if (set_socket_buffers(w->tx_fd) != 0) {
            close(w->tx_fd);
            munmap(ring, ring_sz);
            close(w->rx_fd);
            goto cleanup;
        }
        
        log_info("Worker %d: Initialized (RX ring=%luMB)", i, ring_sz / (1024*1024));
        
        /* Start worker thread */
        if (pthread_create(&w->thread, NULL, worker_thread, w) != 0) {
            log_error("Worker %d: pthread_create() failed: %s", i, strerror(errno));
            close(w->tx_fd);
            munmap(ring, ring_sz);
            close(w->rx_fd);
            goto cleanup;
        }
    }
    
    log_info("All %d workers started successfully", NUM_WORKER_THREADS);
    return 0;
    
cleanup:
    afpkt_multithread_cleanup();
    return -1;
}

void afpkt_multithread_cleanup(void)
{
    log_info("Stopping workers...");
    
    /* Stop all workers */
    for (int i = 0; i < g_state.num_workers; i++) {
        g_state.workers[i].running = 0;
    }
    
    /* Wait for threads */
    for (int i = 0; i < g_state.num_workers; i++) {
        worker_ctx_t *w = &g_state.workers[i];
        if (w->thread) {
            pthread_join(w->thread, NULL);
        }
    }
    
    /* Cleanup resources */
    unsigned long total_rx = 0, total_tx = 0, total_errors = 0;
    
    for (int i = 0; i < g_state.num_workers; i++) {
        worker_ctx_t *w = &g_state.workers[i];
        
        total_rx += w->rx_packets;
        total_tx += w->tx_packets;
        total_errors += w->tx_errors;
        
        if (w->ring) {
            munmap(w->ring, w->ring_size);
        }
        if (w->rx_fd >= 0) {
            close(w->rx_fd);
        }
        if (w->tx_fd >= 0) {
            close(w->tx_fd);
        }
    }
    
    log_info("Multi-threaded AF_PACKET stopped: rx=%lu, tx=%lu, errors=%lu (loss=%.2f%%)",
             total_rx, total_tx, total_errors,
             total_rx > 0 ? (total_errors * 100.0) / total_rx : 0.0);
}

void afpkt_multithread_print_stats(void)
{
    unsigned long total_rx = 0, total_tx = 0, total_errors = 0;
    
    log_info("=== Worker Statistics ===");
    for (int i = 0; i < g_state.num_workers; i++) {
        worker_ctx_t *w = &g_state.workers[i];
        log_info("  Worker %d: rx=%lu, tx=%lu, errors=%lu",
                 i, w->rx_packets, w->tx_packets, w->tx_errors);
        
        total_rx += w->rx_packets;
        total_tx += w->tx_packets;
        total_errors += w->tx_errors;
    }
    
    log_info("  TOTAL: rx=%lu, tx=%lu, errors=%lu (loss=%.2f%%)",
             total_rx, total_tx, total_errors,
             total_rx > 0 ? (total_errors * 100.0) / total_rx : 0.0);
}
