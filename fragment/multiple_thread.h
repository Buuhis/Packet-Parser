#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>
#include <pthread.h>

#define MAX_PKT 65536
#define SEQ_HEADER_SIZE 4

// Reorder buffer configuration
#define REORDER_BUFFER_SIZE 512
#define REORDER_TIMEOUT_MS 100  // Max wait time for out-of-order packets

// ===== Packet item for queue =====
typedef struct {
    uint8_t data[MAX_PKT];
    int len;
    uint32_t seq_num;  // Sequence number for reordering
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

// ===== Callback function types =====
typedef void (*send_wan_callback_t)(uint8_t *pkt, int len, int wan_idx);
typedef void (*send_local_callback_t)(uint8_t *pkt, int len);

// ===== TX Thread pool structure (Local -> WAN) =====
typedef struct {
    int num_threads;
    packet_queue_t *queue;
    send_wan_callback_t send_callback;
    pthread_t *threads;
    volatile int running;
    pthread_mutex_t *rr_lock;
    int *rr_idx;
    int nwan;
    uint32_t *seq_counter;      // Global sequence counter
    pthread_mutex_t *seq_lock;  // Lock for sequence counter
} tx_thread_pool_t;

// ===== Reorder buffer entry =====
typedef struct {
    uint8_t *data;
    int len;
    uint32_t seq_num;
    uint64_t timestamp;
    int used;
} reorder_entry_t;

// ===== Reorder buffer for RX =====
typedef struct {
    reorder_entry_t entries[REORDER_BUFFER_SIZE];
    uint32_t next_expected_seq;
    pthread_mutex_t mutex;
    send_local_callback_t send_callback;

    // Statistics
    uint64_t packets_received;
    uint64_t packets_delivered;
    uint64_t packets_reordered;
    uint64_t packets_dropped;
} reorder_buffer_t;

// ===== Queue Functions =====
void packet_queue_init(packet_queue_t *queue, int max_size);
int packet_queue_push(packet_queue_t *queue, packet_item_t *packet);
packet_item_t* packet_queue_pop(packet_queue_t *queue);
void packet_queue_shutdown(packet_queue_t *queue);
void packet_queue_destroy(packet_queue_t *queue);
int packet_queue_size(packet_queue_t *queue);

// ===== TX Thread Pool Functions (Local -> WAN) =====
tx_thread_pool_t* tx_pool_create(int num_threads, int queue_max_size,
                                  send_wan_callback_t callback,
                                  pthread_mutex_t *rr_lock,
                                  int *rr_idx,
                                  int nwan,
                                  uint32_t *seq_counter,
                                  pthread_mutex_t *seq_lock);
int tx_pool_submit(tx_thread_pool_t *pool, uint8_t *pkt, int len);
void tx_pool_shutdown(tx_thread_pool_t *pool);
void tx_pool_destroy(tx_thread_pool_t *pool);

// ===== Reorder Buffer Functions =====
reorder_buffer_t* reorder_buffer_create(send_local_callback_t callback);
void reorder_buffer_destroy(reorder_buffer_t *buffer);
int reorder_buffer_insert(reorder_buffer_t *buffer, const uint8_t *pkt, int len, uint32_t seq_num);
void reorder_buffer_flush_timeout(reorder_buffer_t *buffer);
void reorder_buffer_print_stats(reorder_buffer_t *buffer);

// ===== Utility Functions =====
uint64_t get_milliseconds(void);

#endif // PACKET_QUEUE_H
