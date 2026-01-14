#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>
#include <pthread.h>

#define MAX_PKT 65536
#define UUID_T_LENGTH 16
#define PACKET_UDP_PORT 9999

// IP and UDP header sizes
#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8

// Packet wrapper header: [Magic 2B][UUID 16B][seq 4B] = 22 bytes
#define PACKET_WRAPPER_MAGIC 0xFE02
#define PACKET_WRAPPER_HEADER_SIZE 22

// Reorder buffer configuration
#define REORDER_BUFFER_SIZE 256
#define REORDER_TIMEOUT_MS 100  // Max wait time for out-of-order packets

typedef uint8_t uuid_t[UUID_T_LENGTH];

// ===== Packet item for queue =====
typedef struct {
    uint8_t data[MAX_PKT];
    int len;
    int wan_idx;
    uuid_t uuid;
    uint64_t timestamp;
    uint32_t seq_num;           // Sequence number for ordering
} packet_item_t;

// ===== Queue node =====
typedef struct packet_node {
    packet_item_t *packet;
    struct packet_node *next;
} packet_node_t;

// ===== Queue structure =====
typedef struct {
    packet_node_t *head;
    packet_node_t *tail;
    int size;
    int max_size;
    pthread_mutex_t mutex;
    pthread_cond_t cond_not_empty;
    pthread_cond_t cond_not_full;
    volatile int shutdown;
} packet_queue_t;

// ===== Callback function type =====
typedef void (*send_wan_callback_t)(uint8_t *pkt, int len,
                                     int wan_idx, const uuid_t uuid);

// ===== Reorder buffer entry =====
typedef struct reorder_entry {
    uint8_t *data;
    int len;
    uint32_t seq_num;
    uint64_t timestamp;
    int used;
} reorder_entry_t;

// ===== Reorder buffer for RX =====
typedef struct {
    reorder_entry_t entries[REORDER_BUFFER_SIZE];
    uint32_t next_expected_seq;     // Next sequence number to deliver
    pthread_mutex_t mutex;

    void (*send_to_local_callback)(uint8_t *pkt, int len);

    // Statistics
    uint64_t packets_received;
    uint64_t packets_delivered;
    uint64_t packets_reordered;
    uint64_t packets_dropped;
} reorder_buffer_t;

// ===== Thread pool structure =====
typedef struct {
    int num_threads;
    packet_queue_t *queue;
    send_wan_callback_t send_callback;
    pthread_t *threads;
    volatile int running;
    pthread_mutex_t *rr_lock;
    int *rr_idx;
    int nwan;
    uint32_t *seq_counter;          // Global sequence counter
    pthread_mutex_t *seq_lock;      // Lock for sequence counter
} thread_pool_t;

// ===== Queue Functions =====
void packet_queue_init(packet_queue_t *queue, int max_size);
int packet_queue_push(packet_queue_t *queue, packet_item_t *packet);
packet_item_t* packet_queue_pop(packet_queue_t *queue);
void packet_queue_shutdown(packet_queue_t *queue);
void packet_queue_destroy(packet_queue_t *queue);
int packet_queue_size(packet_queue_t *queue);

// ===== UUID/Utility Functions =====
void generate_uuid7(uuid_t uuid);
uint64_t get_milliseconds(void);

// ===== Packet Wrapper Functions =====
// Wrap original packet with header for tracking
int wrap_packet_for_wan(const uint8_t *original_pkt, int original_len,
                         const uuid_t uuid, uint32_t seq_num,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint8_t *out_buffer, int *out_len);

// Unwrap packet and extract metadata
int unwrap_packet_from_wan(const uint8_t *wrapped_pkt, int wrapped_len,
                            uuid_t uuid, uint32_t *seq_num,
                            uint8_t *original_pkt, int *original_len);

// Calculate IP checksum
uint16_t calculate_ip_checksum(uint16_t *buf, int len);

// ===== Reorder Buffer Functions =====
reorder_buffer_t* reorder_buffer_create(void (*send_to_local_callback)(uint8_t *pkt, int len));
void reorder_buffer_destroy(reorder_buffer_t *buffer);
int reorder_buffer_insert(reorder_buffer_t *buffer, const uint8_t *pkt, int len, uint32_t seq_num);
void reorder_buffer_flush_timeout(reorder_buffer_t *buffer);
void reorder_buffer_print_stats(reorder_buffer_t *buffer);

// ===== Thread Pool Functions =====
thread_pool_t* thread_pool_create(int num_threads, int queue_max_size,
                                   send_wan_callback_t callback,
                                   pthread_mutex_t *rr_lock,
                                   int *rr_idx,
                                   int nwan,
                                   uint32_t *seq_counter,
                                   pthread_mutex_t *seq_lock);
int thread_pool_submit(thread_pool_t *pool, uint8_t *pkt, int len, int wan_idx);
void thread_pool_shutdown(thread_pool_t *pool);
void thread_pool_destroy(thread_pool_t *pool);

#endif // PACKET_QUEUE_H
