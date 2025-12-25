#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>
#include <pthread.h>

#define MAX_PKT 65536
#define UUID_T_LENGTH 16
#define CHUNK_SIZE 1024  // Kích thước mỗi fragment

typedef uint8_t uuid_t[UUID_T_LENGTH];

// Fragment header: [UUID 16B][seq 4B][total 4B][len 4B] = 28 bytes
#define FRAGMENT_HEADER_SIZE 28

// Cấu trúc chứa thông tin packet cần xử lý
typedef struct {
    uint8_t data[MAX_PKT];     // Original packet data
    int len;                    // Original packet length
    int wan_idx;                // WAN index từ round-robin
    uuid_t uuid;                // UUID cho toàn bộ packet
    uint64_t timestamp;         // Timestamp
    
    // Fragmentation info
    int total_fragments;        // Tổng số fragments
    int current_fragment;       // Fragment hiện tại (cho worker)
} packet_item_t;

// Fragment packet structure
typedef struct {
    uuid_t uuid;                // 16 bytes: UUID của packet gốc
    uint32_t seq;               // 4 bytes: Số thứ tự fragment
    uint32_t total;             // 4 bytes: Tổng số fragments
    uint32_t data_len;          // 4 bytes: Độ dài data trong fragment này
    uint8_t data[CHUNK_SIZE];   // Data của fragment
} __attribute__((packed)) fragment_packet_t;

// Node trong queue
typedef struct packet_node {
    packet_item_t *packet;
    struct packet_node *next;
} packet_node_t;

// Queue structure với thread-safe
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

// Callback function type để send fragment ra WAN
typedef void (*send_wan_callback_t)(uint8_t *fragment_pkt, int len, int wan_idx);

// Cấu trúc config cho thread pool
typedef struct {
    int num_threads;
    packet_queue_t *queue;
    send_wan_callback_t send_callback;
    pthread_t *threads;
    volatile int running;
    int enable_fragmentation;  // Bật/tắt fragmentation
} thread_pool_t;

// ===== Queue Functions =====
void packet_queue_init(packet_queue_t *queue, int max_size);
int packet_queue_push(packet_queue_t *queue, packet_item_t *packet);
packet_item_t* packet_queue_pop(packet_queue_t *queue);
void packet_queue_shutdown(packet_queue_t *queue);
void packet_queue_destroy(packet_queue_t *queue);
int packet_queue_size(packet_queue_t *queue);

// ===== UUID Functions =====
void generate_uuid7(uuid_t uuid);
uint32_t calc_flow_hash(const uuid_t uuid);
uint64_t get_milliseconds(void);

// ===== Fragmentation Functions =====
int calculate_total_fragments(int packet_len);
int build_fragment_packet(const packet_item_t *packet, int fragment_idx, 
                          uint8_t *out_buffer, int *out_len);

// ===== Thread Pool Functions =====
thread_pool_t* thread_pool_create(int num_threads, int queue_max_size, 
                                   send_wan_callback_t callback, 
                                   int enable_fragmentation);
int thread_pool_submit(thread_pool_t *pool, uint8_t *pkt, int len, int wan_idx);
void thread_pool_shutdown(thread_pool_t *pool);
void thread_pool_destroy(thread_pool_t *pool);

#endif // PACKET_QUEUE_H