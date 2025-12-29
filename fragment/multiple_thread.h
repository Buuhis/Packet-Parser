#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>
#include <pthread.h>

#define MAX_PKT 65536
#define UUID_T_LENGTH 16
#define CHUNK_SIZE 1024
#define FRAGMENT_MAGIC 0xFE01
#define FRAGMENT_UDP_PORT 9999

// IP and UDP header sizes
#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8

// Fragment payload header: [Magic 2B][UUID 16B][seq 4B][total 4B][len 4B] = 30 bytes
#define FRAGMENT_PAYLOAD_HEADER_SIZE 30

// Fragment Buffer Configuration
#define FRAGMENT_BUFFER_HASH_SIZE 256
#define FRAGMENT_BUFFER_MAX_AGE_MS 30000

typedef uint8_t uuid_t[UUID_T_LENGTH];

// Packet item structure
typedef struct {
    uint8_t data[MAX_PKT];
    int len;
    int wan_idx;
    uuid_t uuid;
    uint64_t timestamp;
    
    int total_fragments;
    int current_fragment;
} packet_item_t;

// Queue node
typedef struct packet_node {
    packet_item_t *packet;
    struct packet_node *next;
} packet_node_t;

// Queue structure
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

// Callback function type
typedef void (*send_wan_callback_t)(uint8_t *pkt, int len, 
                                     int wan_idx, const uuid_t uuid);

// ===== Fragment Buffer Structures =====

typedef struct fragment_entry {
    int fragment_seq;
    uint8_t *fragment_data;  // Complete IP+UDP+payload packet
    int fragment_len;
    uint64_t timestamp;
    struct fragment_entry *next;
} fragment_entry_t;

typedef struct packet_fragments {
    uuid_t uuid;
    int total_fragments;
    int wan_idx;
    uint64_t timestamp;
    fragment_entry_t *fragments;
    struct packet_fragments *next;
} packet_fragments_t;

typedef struct {
    packet_fragments_t *hash_table[FRAGMENT_BUFFER_HASH_SIZE];
    pthread_mutex_t mutex;
    uint64_t cleanup_interval_ms;
    uint64_t last_cleanup_ms;
} fragment_buffer_t;

// Thread pool structure
typedef struct {
    int num_threads;
    packet_queue_t *queue;
    send_wan_callback_t send_callback;
    pthread_t *threads;
    volatile int running;
    int enable_fragmentation;
    fragment_buffer_t *fragment_buffer;
    pthread_mutex_t *rr_lock;
    int *rr_idx;
    int nwan;
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

// Build fragment with IP/UDP wrapper
int build_fragment_packet(const packet_item_t *packet, int fragment_idx,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint8_t *out_buffer, int *out_len);

// Wrap fragment payload into UDP packet
int wrap_fragment_in_udp(const uint8_t *fragment_payload, int payload_len,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint8_t *out_buffer, int *out_len);

// Calculate IP checksum
uint16_t calculate_ip_checksum(uint16_t *buf, int len);

// ===== Fragment Buffer Functions =====
fragment_buffer_t* fragment_buffer_create(void);
void fragment_buffer_destroy(fragment_buffer_t *buffer);
int store_packet_fragments(fragment_buffer_t *buffer, const packet_item_t *packet,
                           uint32_t src_ip, uint32_t dst_ip);
int get_fragment(fragment_buffer_t *buffer, const uuid_t uuid, int fragment_seq,
                 uint8_t *out_buffer, int *out_len, int *wan_idx);
void fragment_buffer_cleanup(fragment_buffer_t *buffer, uint64_t max_age_ms);

// ===== Thread Pool Functions =====
thread_pool_t* thread_pool_create(int num_threads, int queue_max_size, 
                                   send_wan_callback_t callback, 
                                   int enable_fragmentation,
                                   pthread_mutex_t *rr_lock,
                                   int *rr_idx,
                                   int nwan);
int thread_pool_submit(thread_pool_t *pool, uint8_t *pkt, int len, int wan_idx);
void thread_pool_shutdown(thread_pool_t *pool);
void thread_pool_destroy(thread_pool_t *pool);

#endif // PACKET_QUEUE_H