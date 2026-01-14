#include "packet_queue.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// ===== Utility Functions =====

uint64_t get_milliseconds(void) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return ((uint64_t)tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
}

static void get_random_bytes(uint8_t *buf, size_t len) {
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

// ===== IP/UDP Functions =====

uint16_t calculate_ip_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

// ===== Packet Wrapper Functions =====

int wrap_packet_for_wan(const uint8_t *original_pkt, int original_len,
                         const uuid_t uuid, uint32_t seq_num,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint8_t *out_buffer, int *out_len) {
    if (!original_pkt || !out_buffer || !out_len) {
        return -1;
    }

    // Wrapper payload: [Magic 2B][UUID 16B][Seq 4B][Original packet]
    int payload_len = PACKET_WRAPPER_HEADER_SIZE + original_len;
    int total_len = IP_HEADER_SIZE + UDP_HEADER_SIZE + payload_len;

    if (total_len > MAX_PKT) {
        return -1;
    }

    uint8_t *ptr = out_buffer;

    // ===== BUILD IP HEADER =====
    struct iphdr *ip = (struct iphdr *)ptr;
    memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(total_len);
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = htonl(src_ip);
    ip->daddr = htonl(dst_ip);
    ip->check = 0;
    ip->check = calculate_ip_checksum((uint16_t *)ip, IP_HEADER_SIZE);

    ptr += IP_HEADER_SIZE;

    // ===== BUILD UDP HEADER =====
    struct udphdr *udp = (struct udphdr *)ptr;
    memset(udp, 0, sizeof(struct udphdr));

    udp->source = htons(PACKET_UDP_PORT);
    udp->dest = htons(PACKET_UDP_PORT);
    udp->len = htons(UDP_HEADER_SIZE + payload_len);
    udp->check = 0;

    ptr += UDP_HEADER_SIZE;

    // ===== BUILD WRAPPER HEADER =====
    // Magic (2 bytes)
    uint16_t magic = htons(PACKET_WRAPPER_MAGIC);
    memcpy(ptr, &magic, 2);
    ptr += 2;

    // UUID (16 bytes)
    memcpy(ptr, uuid, UUID_T_LENGTH);
    ptr += UUID_T_LENGTH;

    // Sequence number (4 bytes)
    uint32_t seq_network = htonl(seq_num);
    memcpy(ptr, &seq_network, 4);
    ptr += 4;

    // ===== COPY ORIGINAL PACKET =====
    memcpy(ptr, original_pkt, original_len);

    *out_len = total_len;

    return 0;
}

int unwrap_packet_from_wan(const uint8_t *wrapped_pkt, int wrapped_len,
                            uuid_t uuid, uint32_t *seq_num,
                            uint8_t *original_pkt, int *original_len) {
    if (!wrapped_pkt || !uuid || !seq_num || !original_pkt || !original_len) {
        return -1;
    }

    if (wrapped_len < PACKET_WRAPPER_HEADER_SIZE) {
        return -1;
    }

    const uint8_t *ptr = wrapped_pkt;

    // Magic (2 bytes)
    uint16_t magic;
    memcpy(&magic, ptr, 2);
    magic = ntohs(magic);
    if (magic != PACKET_WRAPPER_MAGIC) {
        return -1;
    }
    ptr += 2;

    // UUID (16 bytes)
    memcpy(uuid, ptr, UUID_T_LENGTH);
    ptr += UUID_T_LENGTH;

    // Sequence number (4 bytes)
    uint32_t seq_network;
    memcpy(&seq_network, ptr, 4);
    *seq_num = ntohl(seq_network);
    ptr += 4;

    // Original packet
    int orig_len = wrapped_len - PACKET_WRAPPER_HEADER_SIZE;
    if (orig_len <= 0 || orig_len > MAX_PKT) {
        return -1;
    }

    memcpy(original_pkt, ptr, orig_len);
    *original_len = orig_len;

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

// ===== Reorder Buffer Implementation =====

reorder_buffer_t* reorder_buffer_create(void (*send_to_local_callback)(uint8_t *pkt, int len)) {
    reorder_buffer_t *buffer = calloc(1, sizeof(reorder_buffer_t));
    if (!buffer) {
        return NULL;
    }

    pthread_mutex_init(&buffer->mutex, NULL);
    buffer->send_to_local_callback = send_to_local_callback;
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

        // Deliver this packet
        if (buffer->send_to_local_callback && entry->data) {
            buffer->send_to_local_callback(entry->data, entry->len);
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
        printf("[REORDER] Dropping old packet seq=%u (expected >= %u)\n",
               seq_num, buffer->next_expected_seq);
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
                if (buffer->send_to_local_callback) {
                    buffer->send_to_local_callback(entry->data, entry->len);
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
        printf("[REORDER] Slot collision: dropping seq=%u for new seq=%u\n",
               entry->seq_num, seq_num);
        if (entry->data) {
            free(entry->data);
        }
        buffer->packets_dropped++;
    }

    // Store packet
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
        printf("[REORDER] Out-of-order: got seq=%u, expected=%u\n",
               seq_num, buffer->next_expected_seq);
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
    int flushed = 0;

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
                flushed = 1;
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

    printf("==============================================\n\n");

    pthread_mutex_unlock(&buffer->mutex);
}

// ===== Thread Pool Implementation =====

static void* thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    uint8_t wrapped_buffer[MAX_PKT];

    printf("[Thread %lu] Worker started\n", pthread_self());

    while (pool->running) {
        packet_item_t *packet = packet_queue_pop(pool->queue);

        if (!packet) {
            break;
        }

        // Extract IP addresses from original packet
        struct iphdr *orig_ip = (struct iphdr *)packet->data;
        uint32_t src_ip = ntohl(orig_ip->saddr);
        uint32_t dst_ip = ntohl(orig_ip->daddr);

        // Get next sequence number
        pthread_mutex_lock(pool->seq_lock);
        uint32_t seq_num = (*pool->seq_counter)++;
        pthread_mutex_unlock(pool->seq_lock);

        packet->seq_num = seq_num;

        // Round robin select WAN
        pthread_mutex_lock(pool->rr_lock);
        int wan_idx = (*pool->rr_idx)++ % pool->nwan;
        pthread_mutex_unlock(pool->rr_lock);

        // Wrap packet with header for tracking
        int wrapped_len;
        if (wrap_packet_for_wan(packet->data, packet->len,
                                 packet->uuid, seq_num,
                                 src_ip, dst_ip,
                                 wrapped_buffer, &wrapped_len) == 0) {

            if (pool->send_callback) {
                pool->send_callback(wrapped_buffer, wrapped_len, wan_idx, packet->uuid);
            }

            printf("[Thread %lu] Sent packet: seq=%u, len=%d, wan=%d\n",
                   pthread_self(), seq_num, packet->len, wan_idx);
        } else {
            fprintf(stderr, "[Thread %lu] Failed to wrap packet\n", pthread_self());
        }

        free(packet);
    }

    printf("[Thread %lu] Worker stopped\n", pthread_self());
    return NULL;
}

thread_pool_t* thread_pool_create(int num_threads, int queue_max_size,
                                   send_wan_callback_t callback,
                                   pthread_mutex_t *rr_lock,
                                   int *rr_idx,
                                   int nwan,
                                   uint32_t *seq_counter,
                                   pthread_mutex_t *seq_lock) {
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
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
        if (pthread_create(&pool->threads[i], NULL, thread_worker, pool) != 0) {
            pool->num_threads = i;
            thread_pool_shutdown(pool);
            thread_pool_destroy(pool);
            return NULL;
        }
    }

    printf("[Thread Pool] Created with %d workers\n", num_threads);

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
