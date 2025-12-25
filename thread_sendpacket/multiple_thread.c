#include "packet_queue.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>

// ===== Utility Functions =====

uint64_t get_milliseconds(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return ((uint64_t)tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
}

void get_random_bytes(uint8_t *buf, size_t len) {
    if (getentropy(buf, len) == -1) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = rand() & 0xFF;
        }
    }
}

void generate_uuid7(uuid_t uuid) {
    uint64_t ts = get_milliseconds();
    
    for (int i = 0; i < 6; i++) {
        uuid[i] = (ts >> ((5 - i) * 8)) & 0xFF;
    }
    
    get_random_bytes(uuid + 6, 10);
    uuid[6] = 0x70 | (uuid[6] & 0x0F);
    uuid[8] = 0x80 | (uuid[8] & 0x3F);
}

uint32_t calc_flow_hash(const uuid_t uuid) {
    uint32_t hash = 0;
    for (int i = 0; i < UUID_T_LENGTH; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash;
}

// ===== Fragmentation Functions =====

int calculate_total_fragments(int packet_len) {
    return (packet_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
}

int build_fragment_packet(const packet_item_t *packet, int fragment_idx,
                          uint8_t *out_buffer, int *out_len) {
    if (!packet || !out_buffer || !out_len) {
        return -1;
    }
    
    if (fragment_idx < 0 || fragment_idx >= packet->total_fragments) {
        return -1;
    }
    
    // Calculate offset và length cho fragment này
    int offset = fragment_idx * CHUNK_SIZE;
    int remaining = packet->len - offset;
    int data_len = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
    
    // Build fragment packet: [UUID 16B][seq 4B][total 4B][len 4B][data]
    uint8_t *ptr = out_buffer;
    
    // UUID (16 bytes)
    memcpy(ptr, packet->uuid, UUID_T_LENGTH);
    ptr += UUID_T_LENGTH;
    
    // Sequence number (4 bytes, network byte order)
    uint32_t seq = htonl(fragment_idx);
    memcpy(ptr, &seq, 4);
    ptr += 4;
    
    // Total fragments (4 bytes, network byte order)
    uint32_t total = htonl(packet->total_fragments);
    memcpy(ptr, &total, 4);
    ptr += 4;
    
    // Data length (4 bytes, network byte order)
    uint32_t len = htonl(data_len);
    memcpy(ptr, &len, 4);
    ptr += 4;
    
    // Data
    memcpy(ptr, packet->data + offset, data_len);
    
    *out_len = FRAGMENT_HEADER_SIZE + data_len;
    
    return 0;
}

// ===== Queue Implementation =====

void packet_queue_init(packet_queue_t *queue, int max_size) {
    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->max_size = max_size;
    queue->shutdown = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond_not_empty, NULL);
    pthread_cond_init(&queue->cond_not_full, NULL);
}

int packet_queue_push(packet_queue_t *queue, packet_item_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->size >= queue->max_size && !queue->shutdown) {
        pthread_cond_wait(&queue->cond_not_full, &queue->mutex);
    }
    
    if (queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    packet_node_t *node = malloc(sizeof(packet_node_t));
    if (!node) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    node->packet = packet;
    node->next = NULL;
    
    if (queue->tail) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }
    queue->tail = node;
    queue->size++;
    
    pthread_cond_signal(&queue->cond_not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

packet_item_t* packet_queue_pop(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->size == 0 && !queue->shutdown) {
        pthread_cond_wait(&queue->cond_not_empty, &queue->mutex);
    }
    
    if (queue->shutdown && queue->size == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }
    
    packet_node_t *node = queue->head;
    queue->head = node->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->size--;
    
    pthread_cond_signal(&queue->cond_not_full);
    pthread_mutex_unlock(&queue->mutex);
    
    packet_item_t *packet = node->packet;
    free(node);
    
    return packet;
}

void packet_queue_shutdown(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->cond_not_empty);
    pthread_cond_broadcast(&queue->cond_not_full);
    pthread_mutex_unlock(&queue->mutex);
}

void packet_queue_destroy(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->head) {
        packet_node_t *node = queue->head;
        queue->head = node->next;
        free(node->packet);
        free(node);
    }
    
    pthread_mutex_unlock(&queue->mutex);
    
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond_not_empty);
    pthread_cond_destroy(&queue->cond_not_full);
}

int packet_queue_size(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    int size = queue->size;
    pthread_mutex_unlock(&queue->mutex);
    return size;
}

// ===== Thread Pool Implementation =====

static void* thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    uint8_t fragment_buffer[FRAGMENT_HEADER_SIZE + CHUNK_SIZE];
    
    while (pool->running) {
        packet_item_t *packet = packet_queue_pop(pool->queue);
        
        if (!packet) {
            break;
        }
        
        uint32_t flow_hash = calc_flow_hash(packet->uuid);
        
        if (pool->enable_fragmentation && packet->len > CHUNK_SIZE) {
            // MODE 1: FRAGMENTATION - Chia packet thành nhiều fragments
            printf("[Thread %lu] Processing packet with FRAGMENTATION:\n", pthread_self());
            printf("  UUID: ");
            for (int i = 0; i < 16; i++) printf("%02x", packet->uuid[i]);
            printf("\n");
            printf("  Flow: %08X | Size: %d bytes | Fragments: %d | WAN: %d\n",
                   flow_hash, packet->len, packet->total_fragments, packet->wan_idx);
            
            // Gửi từng fragment
            for (int i = 0; i < packet->total_fragments; i++) {
                int fragment_len;
                if (build_fragment_packet(packet, i, fragment_buffer, &fragment_len) == 0) {
                    // Gửi fragment qua callback
                    if (pool->send_callback) {
                        pool->send_callback(fragment_buffer, fragment_len, packet->wan_idx);
                    }
                    
                    printf("  [Fragment %d/%d] Sent %d bytes (header=28, data=%d)\n",
                           i + 1, packet->total_fragments, fragment_len, fragment_len - 28);
                    
                    // Delay nhỏ giữa các fragments để tránh burst
                    usleep(500);
                } else {
                    fprintf(stderr, "  [ERROR] Failed to build fragment %d\n", i);
                }
            }
            
            printf("  [COMPLETE] All %d fragments sent to WAN[%d]\n\n",
                   packet->total_fragments, packet->wan_idx);
            
        } else {
            // MODE 2: NO FRAGMENTATION - Gửi packet nguyên vẹn
            if (pool->send_callback) {
                pool->send_callback(packet->data, packet->len, packet->wan_idx);
            }
            
            printf("[Thread %lu] Sent packet WITHOUT fragmentation: len=%d, wan=%d, flow=%08X\n",
                   pthread_self(), packet->len, packet->wan_idx, flow_hash);
        }
        
        free(packet);
    }
    
    return NULL;
}

thread_pool_t* thread_pool_create(int num_threads, int queue_max_size,
                                   send_wan_callback_t callback,
                                   int enable_fragmentation) {
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (!pool) {
        return NULL;
    }
    
    pool->num_threads = num_threads;
    pool->send_callback = callback;
    pool->running = 1;
    pool->enable_fragmentation = enable_fragmentation;
    
    pool->queue = malloc(sizeof(packet_queue_t));
    if (!pool->queue) {
        free(pool);
        return NULL;
    }
    packet_queue_init(pool->queue, queue_max_size);
    
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        packet_queue_destroy(pool->queue);
        free(pool->queue);
        free(pool);
        return NULL;
    }
    
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_worker, pool) != 0) {
            pool->num_threads = i;
            thread_pool_shutdown(pool);
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    
    printf("[Thread Pool] Created with %d workers, fragmentation=%s\n",
           num_threads, enable_fragmentation ? "ENABLED" : "DISABLED");
    
    return pool;
}

int thread_pool_submit(thread_pool_t *pool, uint8_t *pkt, int len, int wan_idx) {
    if (!pool || !pkt || len <= 0) {
        return -1;
    }
    
    packet_item_t *packet = malloc(sizeof(packet_item_t));
    if (!packet) {
        return -1;
    }
    
    memcpy(packet->data, pkt, len);
    packet->len = len;
    packet->wan_idx = wan_idx;
    packet->timestamp = get_milliseconds();
    
    generate_uuid7(packet->uuid);
    
    // Calculate fragmentation info
    packet->total_fragments = calculate_total_fragments(len);
    packet->current_fragment = 0;
    
    if (packet_queue_push(pool->queue, packet) < 0) {
        free(packet);
        return -1;
    }
    
    return 0;
}

void thread_pool_shutdown(thread_pool_t *pool) {
    if (!pool) {
        return;
    }
    
    pool->running = 0;
    packet_queue_shutdown(pool->queue);
    
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
}

void thread_pool_destroy(thread_pool_t *pool) {
    if (!pool) {
        return;
    }
    
    if (pool->queue) {
        packet_queue_destroy(pool->queue);
        free(pool->queue);
    }
    
    if (pool->threads) {
        free(pool->threads);
    }
    
    free(pool);
}