#include "multiple_thread.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

// ===== Utility Functions =====

uint64_t get_milliseconds(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return ((uint64_t)tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
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

// ===== TX Thread Pool Implementation (Local -> WAN) =====

static void* tx_worker(void *arg) {
    tx_thread_pool_t *pool = (tx_thread_pool_t *)arg;
    uint8_t send_buffer[MAX_PKT + SEQ_HEADER_SIZE];

    printf("[TX Thread %lu] Worker started\n", pthread_self());

    while (pool->running) {
        packet_item_t *packet = packet_queue_pop(pool->queue);

        if (!packet) {
            break;
        }

        // Get next sequence number
        pthread_mutex_lock(pool->seq_lock);
        uint32_t seq_num = (*pool->seq_counter)++;
        pthread_mutex_unlock(pool->seq_lock);

        // Round robin select WAN
        pthread_mutex_lock(pool->rr_lock);
        int wan_idx = (*pool->rr_idx)++ % pool->nwan;
        pthread_mutex_unlock(pool->rr_lock);

        // Prepend sequence number to packet: [Seq 4B][Original Packet]
        uint32_t seq_network = htonl(seq_num);
        memcpy(send_buffer, &seq_network, SEQ_HEADER_SIZE);
        memcpy(send_buffer + SEQ_HEADER_SIZE, packet->data, packet->len);
        int total_len = SEQ_HEADER_SIZE + packet->len;

        // Send packet with sequence header to WAN
        if (pool->send_callback) {
            pool->send_callback(send_buffer, total_len, wan_idx);
        }

        free(packet);
    }

    printf("[TX Thread %lu] Worker stopped\n", pthread_self());
    return NULL;
}

tx_thread_pool_t* tx_pool_create(int num_threads, int queue_max_size,
                                  send_wan_callback_t callback,
                                  pthread_mutex_t *rr_lock,
                                  int *rr_idx,
                                  int nwan,
                                  uint32_t *seq_counter,
                                  pthread_mutex_t *seq_lock) {
    tx_thread_pool_t *pool = malloc(sizeof(tx_thread_pool_t));
    if (!pool) {
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->send_callback = callback;
    pool->running = 1;
    pool->rr_lock = rr_lock;
    pool->rr_idx = rr_idx;
    pool->nwan = nwan;
    pool->seq_counter = seq_counter;
    pool->seq_lock = seq_lock;

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
        if (pthread_create(&pool->threads[i], NULL, tx_worker, pool) != 0) {
            pool->num_threads = i;
            tx_pool_shutdown(pool);
            tx_pool_destroy(pool);
            return NULL;
        }
    }

    printf("[TX Pool] Created with %d workers\n", num_threads);

    return pool;
}

int tx_pool_submit(tx_thread_pool_t *pool, uint8_t *pkt, int len) {
    if (!pool || !pkt || len <= 0) {
        return -1;
    }

    packet_item_t *packet = malloc(sizeof(packet_item_t));
    if (!packet) {
        return -1;
    }

    memcpy(packet->data, pkt, len);
    packet->len = len;

    if (packet_queue_push(pool->queue, packet) < 0) {
        free(packet);
        return -1;
    }

    return 0;
}

void tx_pool_shutdown(tx_thread_pool_t *pool) {
    if (!pool) {
        return;
    }

    pool->running = 0;
    packet_queue_shutdown(pool->queue);

    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
}

void tx_pool_destroy(tx_thread_pool_t *pool) {
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

// ===== Reorder Buffer Implementation =====

reorder_buffer_t* reorder_buffer_create(send_local_callback_t callback) {
    reorder_buffer_t *buffer = calloc(1, sizeof(reorder_buffer_t));
    if (!buffer) {
        return NULL;
    }

    pthread_mutex_init(&buffer->mutex, NULL);
    buffer->send_callback = callback;
    buffer->next_expected_seq = 0;

    printf("[REORDER] Buffer created, expecting seq starting from 0\n");

    return buffer;
}

void reorder_buffer_destroy(reorder_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    pthread_mutex_lock(&buffer->mutex);

    for (int i = 0; i < REORDER_BUFFER_SIZE; i++) {
        if (buffer->entries[i].data) {
            free(buffer->entries[i].data);
        }
    }

    pthread_mutex_unlock(&buffer->mutex);
    pthread_mutex_destroy(&buffer->mutex);
    free(buffer);
}

// Try to deliver in-order packets
static void try_deliver_packets(reorder_buffer_t *buffer) {
    while (1) {
        int slot = buffer->next_expected_seq % REORDER_BUFFER_SIZE;
        reorder_entry_t *entry = &buffer->entries[slot];

        if (!entry->used || entry->seq_num != buffer->next_expected_seq) {
            break;  // Gap in sequence or slot empty
        }

        // Deliver this packet (original packet without seq header)
        if (buffer->send_callback && entry->data) {
            buffer->send_callback(entry->data, entry->len);
            buffer->packets_delivered++;
        }

        // Free and mark as unused
        free(entry->data);
        entry->data = NULL;
        entry->used = 0;

        buffer->next_expected_seq++;
    }
}

int reorder_buffer_insert(reorder_buffer_t *buffer, const uint8_t *pkt, int len, uint32_t seq_num) {
    if (!buffer || !pkt || len <= 0) {
        return -1;
    }

    pthread_mutex_lock(&buffer->mutex);

    buffer->packets_received++;

    // Check if packet is too old (already delivered or way behind)
    if (seq_num < buffer->next_expected_seq) {
        buffer->packets_dropped++;
        pthread_mutex_unlock(&buffer->mutex);
        return 0;
    }

    // Check if packet is too far ahead
    if (seq_num >= buffer->next_expected_seq + REORDER_BUFFER_SIZE) {
        printf("[REORDER] Packet seq=%u too far ahead (expected=%u), forcing delivery\n",
               seq_num, buffer->next_expected_seq);

        // Force deliver whatever we have and reset
        for (int i = 0; i < REORDER_BUFFER_SIZE; i++) {
            reorder_entry_t *entry = &buffer->entries[i];
            if (entry->used && entry->data) {
                if (buffer->send_callback) {
                    buffer->send_callback(entry->data, entry->len);
                    buffer->packets_delivered++;
                }
                free(entry->data);
                entry->data = NULL;
                entry->used = 0;
            }
        }
        buffer->next_expected_seq = seq_num;
    }

    int slot = seq_num % REORDER_BUFFER_SIZE;
    reorder_entry_t *entry = &buffer->entries[slot];

    // If slot is used by different seq, drop old one
    if (entry->used && entry->seq_num != seq_num) {
        if (entry->data) {
            free(entry->data);
        }
        buffer->packets_dropped++;
    }

    // Store packet (original packet data)
    entry->data = malloc(len);
    if (!entry->data) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    memcpy(entry->data, pkt, len);
    entry->len = len;
    entry->seq_num = seq_num;
    entry->timestamp = get_milliseconds();
    entry->used = 1;

    if (seq_num != buffer->next_expected_seq) {
        buffer->packets_reordered++;
    }

    // Try to deliver in-order packets
    try_deliver_packets(buffer);

    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

void reorder_buffer_flush_timeout(reorder_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    pthread_mutex_lock(&buffer->mutex);

    uint64_t current_time = get_milliseconds();

    // Check if we have packets waiting too long
    for (int i = 0; i < REORDER_BUFFER_SIZE; i++) {
        reorder_entry_t *entry = &buffer->entries[i];

        if (entry->used && entry->data) {
            uint64_t age = current_time - entry->timestamp;

            if (age > REORDER_TIMEOUT_MS && entry->seq_num > buffer->next_expected_seq) {
                // Skip ahead to this packet
                printf("[REORDER] Timeout: skipping from seq=%u to seq=%u (waited %lums)\n",
                       buffer->next_expected_seq, entry->seq_num, (unsigned long)age);

                buffer->next_expected_seq = entry->seq_num;
                try_deliver_packets(buffer);
                break;
            }
        }
    }

    pthread_mutex_unlock(&buffer->mutex);
}

void reorder_buffer_print_stats(reorder_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    pthread_mutex_lock(&buffer->mutex);

    printf("\n========== REORDER BUFFER STATISTICS ==========\n");
    printf("Packets received:    %lu\n", (unsigned long)buffer->packets_received);
    printf("Packets delivered:   %lu\n", (unsigned long)buffer->packets_delivered);
    printf("Packets reordered:   %lu\n", (unsigned long)buffer->packets_reordered);
    printf("Packets dropped:     %lu\n", (unsigned long)buffer->packets_dropped);
    printf("Next expected seq:   %u\n", buffer->next_expected_seq);

    if (buffer->packets_received > 0) {
        double reorder_rate = (double)buffer->packets_reordered / buffer->packets_received * 100.0;
        printf("Reorder rate:        %.2f%%\n", reorder_rate);
    }

    printf("================================================\n\n");

    pthread_mutex_unlock(&buffer->mutex);
}
