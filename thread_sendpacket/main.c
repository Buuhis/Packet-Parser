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
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "packet_queue.h"

#define MAX_PKT 65536
#define MAX_WAN 10
#define NUM_WORKER_THREADS 4
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
static thread_pool_t *worker_pool = NULL;

void handle_signal(int sig) {
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

void send_to_local(uint8_t *pkt, int len) {
    struct iphdr *ip = (struct iphdr *)pkt;

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = cfg.local_idx;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);

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

// Callback function được gọi bởi worker threads để send packet ra WAN
void send_to_wan_callback(uint8_t *pkt, int len, int wan_idx, const uuid_t uuid) {
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
    }
    
    // Optional: Log để debug
    // uint32_t flow_hash = calc_flow_hash(uuid);
    // printf("Sent %zd bytes to WAN[%d] (flow: %08X)\n", sent, wan_idx, flow_hash);
}

void *capture_local(void *arg) {
    uint8_t buf[MAX_PKT];
    
    while (running) {
        int n = recv(cfg.local_fd, buf, sizeof(buf), 0);
        if (n < (int)sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buf;
        uint32_t dip = ntohl(ip->daddr);

        // Filter: chỉ xử lý packet đến remote network
        if ((dip & cfg.remote_mask) != (cfg.remote_ip & cfg.remote_mask)) {
            continue;
        }

        // Filter: chỉ xử lý UDP packets
        if (ip->protocol != IPPROTO_UDP) {
            continue;
        }

        // Round-robin chọn WAN interface
        pthread_mutex_lock(&rr_lock);
        int idx = cfg.rr_idx++ % cfg.nwan;
        pthread_mutex_unlock(&rr_lock);

        // Submit packet vào thread pool thay vì send trực tiếp
        if (thread_pool_submit(worker_pool, buf, n, idx) < 0) {
            fprintf(stderr, "Failed to submit packet to thread pool\n");
        }
    }
    
    return NULL;
}

void *capture_wan(void *arg) {
    wan_t *w = (wan_t *)arg;
    uint8_t buf[MAX_PKT];
    
    while (running) {
        int n = recv(w->fd, buf, sizeof(buf), 0);
        if (n < (int)sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buf;
        if (ip->protocol != IPPROTO_UDP) {
            continue;
        }
        
        // Send packet về local network
        send_to_local(buf, n);
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

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

    // Khởi tạo thread pool với worker threads
    // enable_fragmentation: 1 = BẬT chia nhỏ packet, 0 = TẮT 
    int enable_fragmentation = 1;  
    
    printf("Creating thread pool with %d workers (fragmentation=%s)\n", 
           NUM_WORKER_THREADS, enable_fragmentation ? "ON" : "OFF");
    worker_pool = thread_pool_create(NUM_WORKER_THREADS, QUEUE_MAX_SIZE, 
                                     send_to_wan_callback, enable_fragmentation);
    if (!worker_pool) {
        fprintf(stderr, "Failed to create thread pool\n");
        return 1;
    }

    // Tạo thread để capture packets từ local interface
    pthread_t local_tid;
    pthread_create(&local_tid, NULL, capture_local, NULL);

    // Tạo threads để capture packets từ các WAN interfaces
    pthread_t wan_tid[MAX_WAN];
    for (int i = 0; i < cfg.nwan; i++) {
        pthread_create(&wan_tid[i], NULL, capture_wan, &cfg.wan[i]);
    }

    printf("Load balancer started. Press Ctrl+C to stop.\n");
    
    // Main loop
    while (running) {
        sleep(1);
        
        // Optional: Print queue status
        if (worker_pool && worker_pool->queue) {
            int queue_size = packet_queue_size(worker_pool->queue);
            if (queue_size > 0) {
                printf("Queue size: %d packets\n", queue_size);
            }
        }
    }

    printf("\nShutting down...\n");
    
    // Cleanup
    pthread_join(local_tid, NULL);
    for (int i = 0; i < cfg.nwan; i++) {
        pthread_join(wan_tid[i], NULL);
    }
    
    if (worker_pool) {
        thread_pool_shutdown(worker_pool);
        thread_pool_destroy(worker_pool);
    }

    // Close sockets
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