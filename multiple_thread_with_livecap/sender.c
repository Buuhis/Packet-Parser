#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <stdint.h>
#include <sys/random.h>
#include <pthread.h>
#include <sys/ioctl.h>

#define DEST_PORT 2345
#define CHUNK 512
#define UUID_T_LENGTH 16
#define NUM_THREADS 10
#define MAX_PACKET_SIZE 65536
#define MAX_WAN_INTERFACES 10
#define MAX_LINE_LEN 256

typedef uint8_t uuid_t[UUID_T_LENGTH];

// Configuration structures
typedef struct {
    char interface[32];
    int port;
    char peer_ip[64];
    int peer_port;
    int sock_fd;
} wan_config_t;

typedef struct {
    char local_interface[32];
    wan_config_t wan_interfaces[MAX_WAN_INTERFACES];
    int num_wan;
} config_t;

// Packet structure
typedef struct {
    uuid_t uuid;
    uint8_t *data;
    size_t len;
    struct sockaddr_in src_addr;
    uint64_t timestamp;
} captured_packet_t;

// Queue structures
typedef struct queue_node {
    captured_packet_t *packet;
    struct queue_node *next;
} queue_node_t;

typedef struct {
    queue_node_t *head;
    queue_node_t *tail;
    int size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int done;
} packet_queue_t;

typedef struct {
    wan_config_t *wan_configs;
    int num_wan;
    packet_queue_t *queue;
    int thread_id;
} thread_arg_t;

// Global variables
config_t global_config;
packet_queue_t global_queue;
volatile int running = 1;

// Utility functions
uint64_t get_miliseconds(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return ((uint64_t)tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
}

void get_random_bytes(uint8_t *buf, size_t len) {
    if (getentropy(buf, len) == -1) {
        perror("getentropy");
        exit(1);
    }
}

void generate_uuid7(uuid_t uuid) {
    uint64_t ts = get_miliseconds();
    for (int i = 0; i < 6; i++) {
        uuid[i] = (ts >> ((5 - i) * 8)) & 0xFF;
    }
    get_random_bytes(uuid + 6, 10);
    uuid[6] = 0x70 | (uuid[6] & 0x0F);
    uuid[8] = 0x80 | (uuid[8] & 0x3F);
}

uint32_t calc_flow_hash(const uuid_t uuid) {
    uint32_t hash = 0;
    for (int i = 0; i < 16; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash;
}

// Configuration parsing
void trim_whitespace(char *str) {
    char *end;
    while (*str == ' ' || *str == '\t') str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    *(end + 1) = 0;
}

int parse_config(const char *filename, config_t *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen config");
        return -1;
    }

    char line[MAX_LINE_LEN];
    config->num_wan = 0;
    memset(config->local_interface, 0, sizeof(config->local_interface));

    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0') continue;

        // Parse local interface
        if (strncmp(line, "local ", 6) == 0) {
            sscanf(line + 6, "%s", config->local_interface);
            printf("[CONFIG] Local interface: %s\n", config->local_interface);
        }
        // Parse WAN interface
        else if (strncmp(line, "wan ", 4) == 0) {
            if (config->num_wan >= MAX_WAN_INTERFACES) {
                fprintf(stderr, "Too many WAN interfaces\n");
                continue;
            }

            wan_config_t *wan = &config->wan_interfaces[config->num_wan];
            char local_part[64], peer_part[64];
            
            if (sscanf(line + 4, "%s %s", local_part, peer_part) == 2) {
                // Parse local part: interface:port
                char *colon = strchr(local_part, ':');
                if (colon) {
                    *colon = '\0';
                    strncpy(wan->interface, local_part, sizeof(wan->interface) - 1);
                    wan->port = atoi(colon + 1);
                }

                // Parse peer part: ip:port
                colon = strchr(peer_part, ':');
                if (colon) {
                    *colon = '\0';
                    strncpy(wan->peer_ip, peer_part, sizeof(wan->peer_ip) - 1);
                    wan->peer_port = atoi(colon + 1);
                }

                printf("[CONFIG] WAN %d: %s:%d -> %s:%d\n", 
                       config->num_wan + 1,
                       wan->interface, wan->port,
                       wan->peer_ip, wan->peer_port);
                
                config->num_wan++;
            }
        }
    }

    fclose(fp);
    return 0;
}

// Queue operations
void queue_init(packet_queue_t *queue) {
    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->done = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

void queue_push(packet_queue_t *queue, captured_packet_t *packet) {
    queue_node_t *node = malloc(sizeof(queue_node_t));
    node->packet = packet;
    node->next = NULL;

    pthread_mutex_lock(&queue->mutex);
    if (queue->tail) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }
    queue->tail = node;
    queue->size++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

captured_packet_t* queue_pop(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->size == 0 && !queue->done) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }
    
    if (queue->size == 0 && queue->done) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    queue_node_t *node = queue->head;
    queue->head = node->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->size--;
    pthread_mutex_unlock(&queue->mutex);

    captured_packet_t *packet = node->packet;
    free(node);
    return packet;
}

// Create raw socket for packet capture
int create_capture_socket(const char *interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Bind to specific interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    printf("[CAPTURE] Bound to interface %s (index: %d)\n", interface, ifr.ifr_ifindex);
    return sock;
}

// Packet capture thread
void* capture_thread(void *arg) {
    packet_queue_t *queue = (packet_queue_t *)arg;
    
    int sock = create_capture_socket(global_config.local_interface);
    if (sock < 0) {
        fprintf(stderr, "[CAPTURE] Failed to create capture socket\n");
        return NULL;
    }

    uint8_t buffer[MAX_PACKET_SIZE];
    
    printf("[CAPTURE] Started capturing on %s\n", global_config.local_interface);
    
    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        
        int ret = select(sock + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ret == 0) continue;

        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }

        // Skip Ethernet header (14 bytes)
        if (len < 14) continue;
        
        struct iphdr *ip_header = (struct iphdr *)(buffer + 14);
        
        // Check if it's UDP
        if (ip_header->protocol != IPPROTO_UDP) continue;
        
        int ip_header_len = ip_header->ihl * 4;
        struct udphdr *udp_header = (struct udphdr *)(buffer + 14 + ip_header_len);
        
        // Check if destination port matches
        if (ntohs(udp_header->dest) != DEST_PORT) continue;

        // Extract UDP payload
        int udp_header_len = 8;
        uint8_t *payload = buffer + 14 + ip_header_len + udp_header_len;
        size_t payload_len = len - 14 - ip_header_len - udp_header_len;

        // Create packet structure
        captured_packet_t *packet = malloc(sizeof(captured_packet_t));
        packet->data = malloc(payload_len);
        memcpy(packet->data, payload, payload_len);
        packet->len = payload_len;
        packet->timestamp = get_miliseconds();
        
        packet->src_addr.sin_family = AF_INET;
        packet->src_addr.sin_addr.s_addr = ip_header->saddr;
        packet->src_addr.sin_port = udp_header->source;

        generate_uuid7(packet->uuid);

        printf("[CAPTURE] Packet captured: %zu bytes from %s:%d\n",
               payload_len,
               inet_ntoa(packet->src_addr.sin_addr),
               ntohs(packet->src_addr.sin_port));

        queue_push(queue, packet);
    }

    close(sock);
    printf("[CAPTURE] Capture thread stopped\n");
    return NULL;
}

// Worker thread - processes packets from queue
void* thread_worker(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    int thread_id = targ->thread_id;
    
    printf("[Thread %d] Started\n", thread_id);

    while (1) {
        captured_packet_t *packet = queue_pop(targ->queue);
        if (!packet) {
            printf("[Thread %d] Queue done, exiting\n", thread_id);
            break;
        }

        uint32_t flow_hash = calc_flow_hash(packet->uuid);
        int wan_index = flow_hash % targ->num_wan;
        wan_config_t *wan = &targ->wan_configs[wan_index];

        printf("[Thread %d] Processing packet (flow=%08X) -> WAN %d (%s:%d)\n",
               thread_id, flow_hash, wan_index, wan->peer_ip, wan->peer_port);

        // Create socket for sending
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            free(packet->data);
            free(packet);
            continue;
        }

        struct sockaddr_in dest = {0};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(wan->peer_port);
        inet_pton(AF_INET, wan->peer_ip, &dest.sin_addr);

        // Send packet data in chunks (similar to original logic)
        int total = (packet->len + CHUNK - 1) / CHUNK;
        
        for (int i = 0; i < total; i++) {
            char pkt[CHUNK + 28];
            int offset = i * CHUNK;
            int len = (packet->len - offset > CHUNK) ? CHUNK : (packet->len - offset);
            
            memcpy(pkt, packet->uuid, 16);
            *(int *)(pkt + 16) = htonl(i);
            *(int *)(pkt + 20) = htonl(total);
            *(int *)(pkt + 24) = htonl(len);
            memcpy(pkt + 28, packet->data + offset, len);
            
            sendto(sock, pkt, 28 + len, 0, (struct sockaddr *)&dest, sizeof(dest));
            
            printf("\r[Thread %d] [%d/%d] SENT", thread_id, i + 1, total);
            fflush(stdout);
            usleep(800);
        }
        printf("\n[Thread %d] Packet forwarded successfully\n", thread_id);

        close(sock);
        free(packet->data);
        free(packet);
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse configuration
    if (parse_config(argv[1], &global_config) < 0) {
        fprintf(stderr, "Failed to parse config file\n");
        return EXIT_FAILURE;
    }

    if (global_config.num_wan == 0) {
        fprintf(stderr, "No WAN interfaces configured\n");
        return EXIT_FAILURE;
    }

    printf("\n=== Starting Packet Capture System ===\n");
    printf("Local Interface: %s\n", global_config.local_interface);
    printf("WAN Interfaces: %d\n", global_config.num_wan);
    printf("Worker Threads: %d\n\n", NUM_THREADS);

    // Initialize queue
    queue_init(&global_queue);

    // Create capture thread
    pthread_t capture_tid;
    if (pthread_create(&capture_tid, NULL, capture_thread, &global_queue) != 0) {
        perror("pthread_create capture");
        return EXIT_FAILURE;
    }

    // Create worker threads
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].wan_configs = global_config.wan_interfaces;
        args[i].num_wan = global_config.num_wan;
        args[i].queue = &global_queue;
        args[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, thread_worker, &args[i]) != 0) {
            perror("pthread_create worker");
            return EXIT_FAILURE;
        }
        printf("[MAIN] Created worker thread %d\n", i);
    }

    // Wait for Ctrl+C or other signals
    printf("\n[MAIN] System running. Press Ctrl+C to stop...\n\n");
    
    // Simple signal handling (you should use sigaction in production)
    while (running) {
        sleep(1);
    }

    // Cleanup
    printf("\n[MAIN] Shutting down...\n");
    
    pthread_mutex_lock(&global_queue.mutex);
    global_queue.done = 1;
    pthread_cond_broadcast(&global_queue.cond);
    pthread_mutex_unlock(&global_queue.mutex);

    pthread_join(capture_tid, NULL);
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&global_queue.mutex);
    pthread_cond_destroy(&global_queue.cond);

    printf("[MAIN] System stopped\n");
    return EXIT_SUCCESS;
}