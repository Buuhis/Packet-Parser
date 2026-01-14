#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "multiple_thread.h"

#define MAX_WAN 10
#define NUM_TX_THREADS 4
#define QUEUE_MAX_SIZE 1000

typedef struct {
    char    iface[32];
    int     fd;
    int     idx;
    uint8_t peer_mac[6];
} wan_t;

static struct {
    char        local[32];
    int         local_fd;
    int         local_idx;
    uint32_t    remote_ip;
    uint32_t    remote_mask;
    wan_t       wan[MAX_WAN];
    int         nwan;
    int         rr_idx;
} cfg;

static volatile int running = 1;
static pthread_mutex_t rr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t seq_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t seq_counter = 0;

// TX thread pool
static tx_thread_pool_t *tx_pool = NULL;

// RX reorder buffer
static reorder_buffer_t *reorder_buf = NULL;
static pthread_t timeout_thread;

// Statistics
static uint64_t packets_tx = 0;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

int parse_cidr(const char *s, uint32_t *ip, uint32_t *mask) {
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) {
        *slash = 0;
        prefix = atoi(slash + 1);
    }
    *ip = ntohl(inet_addr(buf));
    *mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    return 0;
}

int get_peer_mac(const char *iface, const char *peer_ip, uint8_t *mac) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", peer_ip);
    system(cmd);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct arpreq req;
    memset(&req, 0, sizeof(req));
    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, peer_ip, &sin->sin_addr);
    strncpy(req.arp_dev, iface, sizeof(req.arp_dev) - 1);

    if (ioctl(fd, SIOCGARP, &req) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, req.arp_ha.sa_data, 6);
    return 0;
}

int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[32], val1[64], val2[64];
        int n = sscanf(line, "%31s %63s %63s", key, val1, val2);
        if (n < 2) {
            continue;
        }

        if (!strcmp(key, "local")) {
            strncpy(cfg.local, val1, sizeof(cfg.local) - 1);
        }
        else if (!strcmp(key, "remote")) {
            parse_cidr(val1, &cfg.remote_ip, &cfg.remote_mask);
        }
        else if (!strcmp(key, "wan") && cfg.nwan < MAX_WAN) {
            wan_t *w = &cfg.wan[cfg.nwan];
            strncpy(w->iface, val1, sizeof(w->iface) - 1);
            if (n >= 3 && get_peer_mac(val1, val2, w->peer_mac) < 0) {
                memset(w->peer_mac, 0xff, 6);
            }
            cfg.nwan++;
        }
    }
    fclose(f);
    return (cfg.nwan > 0) ? 0 : -1;
}

int create_raw_socket(const char *iface, int *idx) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
        return -1;
    }

    *idx = if_nametoindex(iface);
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = *idx;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int init_sockets() {
    cfg.local_fd = create_raw_socket(cfg.local, &cfg.local_idx);
    if (cfg.local_fd < 0) {
        return -1;
    }

    for (int i = 0; i < cfg.nwan; i++) {
        wan_t *w = &cfg.wan[i];
        w->fd = create_raw_socket(w->iface, &w->idx);
        if (w->fd < 0) {
            return -1;
        }
    }
    return 0;
}

// Callback for reorder buffer - send original packet to local interface
void send_to_local(uint8_t *pkt, int len) {
    struct iphdr *ip = (struct iphdr *)pkt;

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = cfg.local_idx;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);

    // Try to get destination MAC from ARP cache
    struct arpreq req;
    memset(&req, 0, sizeof(req));
    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->daddr;
    strncpy(req.arp_dev, cfg.local, sizeof(req.arp_dev) - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        if (ioctl(fd, SIOCGARP, &req) == 0) {
            memcpy(sll.sll_addr, req.arp_ha.sa_data, 6);
        }
        close(fd);
    }

    sendto(cfg.local_fd, pkt, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

// Callback for TX pool - send packet with seq header to WAN interface
void send_to_wan(uint8_t *pkt, int len, int wan_idx) {
    if (wan_idx < 0 || wan_idx >= cfg.nwan) {
        fprintf(stderr, "Invalid WAN index: %d\n", wan_idx);
        return;
    }

    wan_t *w = &cfg.wan[wan_idx];

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = w->idx;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, w->peer_mac, 6);

    ssize_t sent = sendto(w->fd, pkt, len, 0, (struct sockaddr *)&sll, sizeof(sll));

    if (sent < 0) {
        perror("sendto WAN");
    } else {
        pthread_mutex_lock(&stats_lock);
        packets_tx++;
        pthread_mutex_unlock(&stats_lock);
    }
}

// Timeout check thread for reorder buffer
void *timeout_worker(void *arg) {
    (void)arg;

    while (running) {
        usleep(50000);  // Check every 50ms

        if (reorder_buf) {
            reorder_buffer_flush_timeout(reorder_buf);
        }
    }

    return NULL;
}

// ===== CAPTURE THREADS =====

// Capture from local interface -> submit to TX queue -> round robin to WAN
void *capture_local(void *arg) {
    (void)arg;
    uint8_t buf[MAX_PKT];

    printf("[LOCAL] Capture thread started on interface %s\n", cfg.local);

    while (running) {
        int n = recv(cfg.local_fd, buf, sizeof(buf), 0);
        if (n < (int)sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buf;
        uint32_t dip = ntohl(ip->daddr);

        // Filter by destination network
        if ((dip & cfg.remote_mask) != (cfg.remote_ip & cfg.remote_mask)) {
            continue;
        }

        // Only handle UDP packets
        if (ip->protocol != IPPROTO_UDP) {
            continue;
        }

        // Submit to TX pool for round-robin forwarding to WAN
        if (tx_pool_submit(tx_pool, buf, n) < 0) {
            fprintf(stderr, "Failed to submit packet to TX pool\n");
        }
    }

    printf("[LOCAL] Capture thread stopped\n");
    return NULL;
}

// Capture from WAN interface -> extract seq -> insert to reorder buffer -> send original to local
void *capture_wan(void *arg) {
    wan_t *w = (wan_t *)arg;
    uint8_t buf[MAX_PKT];
    int wan_idx = w - cfg.wan;

    printf("[WAN%d] Capture thread started on interface %s\n", wan_idx, w->iface);

    while (running) {
        int n = recv(w->fd, buf, sizeof(buf), 0);
        if (n < (int)sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buf;

        // Only handle UDP packets
        if (ip->protocol != IPPROTO_UDP) {
            continue;
        }

        // Check if packet has seq header (at least SEQ_HEADER_SIZE bytes of payload)
        if (n < SEQ_HEADER_SIZE) {
            continue;
        }

        // Extract sequence number from the beginning of packet
        uint32_t seq_network;
        memcpy(&seq_network, buf, SEQ_HEADER_SIZE);
        uint32_t seq_num = ntohl(seq_network);

        // Get original packet (after seq header)
        uint8_t *original_pkt = buf + SEQ_HEADER_SIZE;
        int original_len = n - SEQ_HEADER_SIZE;

        if (original_len <= 0) {
            continue;
        }

        // Insert into reorder buffer (will deliver in-order to local)
        if (reorder_buf) {
            reorder_buffer_insert(reorder_buf, original_pkt, original_len, seq_num);
        }
    }

    printf("[WAN%d] Capture thread stopped\n", wan_idx);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("==============================================\n");
    printf("  UDP Load Balancer (Round Robin + Reorder)\n");
    printf("  TX: Local -> [Seq+Pkt] -> WAN (round robin)\n");
    printf("  RX: WAN -> Extract Seq -> Reorder -> Local\n");
    printf("==============================================\n\n");

    printf("Loading configuration from %s\n", argv[1]);
    if (load_config(argv[1]) < 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    printf("Initializing sockets for %d WAN interfaces\n", cfg.nwan);
    if (init_sockets() < 0) {
        fprintf(stderr, "Failed to initialize sockets\n");
        return 1;
    }

    // Create reorder buffer for RX
    printf("Creating reorder buffer for RX\n");
    reorder_buf = reorder_buffer_create(send_to_local);
    if (!reorder_buf) {
        fprintf(stderr, "Failed to create reorder buffer\n");
        return 1;
    }

    // Create TX pool (Local -> WAN)
    printf("Creating TX thread pool with %d workers\n", NUM_TX_THREADS);
    tx_pool = tx_pool_create(NUM_TX_THREADS, QUEUE_MAX_SIZE,
                              send_to_wan,
                              &rr_lock, &cfg.rr_idx, cfg.nwan,
                              &seq_counter, &seq_lock);
    if (!tx_pool) {
        fprintf(stderr, "Failed to create TX thread pool\n");
        reorder_buffer_destroy(reorder_buf);
        return 1;
    }

    // Start timeout check thread
    if (pthread_create(&timeout_thread, NULL, timeout_worker, NULL) != 0) {
        fprintf(stderr, "Failed to create timeout thread\n");
        return 1;
    }

    // Start local capture thread
    pthread_t local_tid;
    pthread_create(&local_tid, NULL, capture_local, NULL);

    // Start WAN capture threads
    pthread_t wan_tid[MAX_WAN];
    for (int i = 0; i < cfg.nwan; i++) {
        pthread_create(&wan_tid[i], NULL, capture_wan, &cfg.wan[i]);
    }

    printf("\n==============================================\n");
    printf("  Load balancer started. Press Ctrl+C to stop.\n");
    printf("==============================================\n\n");

    // Main loop - monitor stats
    while (running) {
        sleep(1);

        pthread_mutex_lock(&stats_lock);
        int tx_q = tx_pool ? packet_queue_size(tx_pool->queue) : 0;
        printf("[STATS] TX: %lu (queue: %d) | Seq: %u\n",
               packets_tx, tx_q, seq_counter);
        pthread_mutex_unlock(&stats_lock);
    }

    printf("\nShutting down...\n");

    // Wait for capture threads to finish
    pthread_join(local_tid, NULL);
    for (int i = 0; i < cfg.nwan; i++) {
        pthread_join(wan_tid[i], NULL);
    }
    pthread_join(timeout_thread, NULL);

    // Print statistics
    printf("\n========== FINAL STATISTICS ==========\n");
    printf("Total packets TX (Local->WAN): %lu\n", packets_tx);
    printf("=======================================\n");

    if (reorder_buf) {
        reorder_buffer_print_stats(reorder_buf);
        reorder_buffer_destroy(reorder_buf);
    }

    // Cleanup
    if (tx_pool) {
        tx_pool_shutdown(tx_pool);
        tx_pool_destroy(tx_pool);
    }

    if (cfg.local_fd >= 0) {
        close(cfg.local_fd);
    }
    for (int i = 0; i < cfg.nwan; i++) {
        if (cfg.wan[i].fd >= 0) {
            close(cfg.wan[i].fd);
        }
    }

    printf("Shutdown complete\n");
    return 0;
}
