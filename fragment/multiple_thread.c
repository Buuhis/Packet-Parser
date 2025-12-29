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

int wrap_fragment_in_udp(const uint8_t *fragment_payload, int payload_len,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint8_t *out_buffer, int *out_len) {
    if (!fragment_payload || !out_buffer || !out_len) {
        return -1;
    }
    
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
    
    udp->source = htons(FRAGMENT_UDP_PORT);
    udp->dest = htons(FRAGMENT_UDP_PORT);
    udp->len = htons(UDP_HEADER_SIZE + payload_len);
    udp->check = 0;
    
    ptr += UDP_HEADER_SIZE;
    
    // ===== COPY PAYLOAD =====
    memcpy(ptr, fragment_payload, payload_len);
    
    *out_len = total_len;
    
    return 0;
}

// ===== Fragmentation Functions =====

int calculate_total_fragments(int packet_len) {
    // Fragment data của packet gốc (trừ IP+UDP header nếu có)
    return (packet_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
}

int build_fragment_packet(const packet_item_t *packet, int fragment_idx,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint8_t *out_buffer, int *out_len) {
    if (!packet || !out_buffer || !out_len) {
        return -1;
    }
    
    if (fragment_idx < 0 || fragment_idx >= packet->total_fragments) {
        return -1;
    }
    
    // ===== STEP 1: Build fragment payload =====
    uint8_t fragment_payload[FRAGMENT_PAYLOAD_HEADER_SIZE + CHUNK_SIZE];
    uint8_t *ptr = fragment_payload;
    
    int offset = fragment_idx * CHUNK_SIZE;
    int remaining = packet->len - offset;
    int data_len = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
    
    // Magic number (2 bytes)
    uint16_t magic = htons(FRAGMENT_MAGIC);
    memcpy(ptr, &magic, 2);
    ptr += 2;
    
    // UUID (16 bytes)
    memcpy(ptr, packet->uuid, UUID_T_LENGTH);
    ptr += UUID_T_LENGTH;
    
    // Sequence (4 bytes)
    uint32_t seq = htonl(fragment_idx);
    memcpy(ptr, &seq, 4);
    ptr += 4;
    
    // Total (4 bytes)
    uint32_t total = htonl(packet->total_fragments);
    memcpy(ptr, &total, 4);
    ptr += 4;
    
    // Data length (4 bytes)
    uint32_t len = htonl(data_len);
    memcpy(ptr, &len, 4);
    ptr += 4;
    
    // Data
    memcpy(ptr, packet->data + offset, data_len);
    
    int payload_len = FRAGMENT_PAYLOAD_HEADER_SIZE + data_len;
    
    // ===== STEP 2: Wrap in UDP packet =====
    return wrap_fragment_in_udp(fragment_payload, payload_len,
                                src_ip, dst_ip, out_buffer, out_len);
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

// ===== Fragment Buffer Implementation =====

static uint32_t uuid_hash(const uuid_t uuid) {
    uint32_t hash = 0;
    for (int i = 0; i < UUID_T_LENGTH; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash % FRAGMENT_BUFFER_HASH_SIZE;
}

static int uuid_equal(const uuid_t uuid1, const uuid_t uuid2) {
    return memcmp(uuid1, uuid2, UUID_T_LENGTH) == 0;
}

fragment_buffer_t* fragment_buffer_create(void) {
    fragment_buffer_t *buffer = malloc(sizeof(fragment_buffer_t));
    if (!buffer) {
        return NULL;
    }
    
    memset(buffer->hash_table, 0, sizeof(buffer->hash_table));
    pthread_mutex_init(&buffer->mutex, NULL);
    buffer->cleanup_interval_ms = 5000;
    buffer->last_cleanup_ms = get_milliseconds();
    
    return buffer;
}

void fragment_buffer_destroy(fragment_buffer_t *buffer) {
    if (!buffer) {
        return;
    }
    
    pthread_mutex_lock(&buffer->mutex);
    
    for (int i = 0; i < FRAGMENT_BUFFER_HASH_SIZE; i++) {
        packet_fragments_t *pf = buffer->hash_table[i];
        while (pf) {
            packet_fragments_t *next_pf = pf->next;
            
            fragment_entry_t *fe = pf->fragments;
            while (fe) {
                fragment_entry_t *next_fe = fe->next;
                free(fe->fragment_data);
                free(fe);
                fe = next_fe;
            }
            
            free(pf);
            pf = next_pf;
        }
    }
    
    pthread_mutex_unlock(&buffer->mutex);
    pthread_mutex_destroy(&buffer->mutex);
    free(buffer);
}

int store_packet_fragments(fragment_buffer_t *buffer, const packet_item_t *packet,
                           uint32_t src_ip, uint32_t dst_ip) {
    if (!buffer || !packet) {
        return -1;
    }
    
    if (packet->total_fragments <= 1) {
        return 0;
    }
    
    pthread_mutex_lock(&buffer->mutex);
    
    uint32_t bucket = uuid_hash(packet->uuid);
    uint64_t current_time = get_milliseconds();
    
    packet_fragments_t *pf = buffer->hash_table[bucket];
    while (pf) {
        if (uuid_equal(pf->uuid, packet->uuid)) {
            fragment_entry_t *fe = pf->fragments;
            while (fe) {
                fragment_entry_t *next_fe = fe->next;
                free(fe->fragment_data);
                free(fe);
                fe = next_fe;
            }
            pf->fragments = NULL;
            break;
        }
        pf = pf->next;
    }
    
    if (!pf) {
        pf = malloc(sizeof(packet_fragments_t));
        if (!pf) {
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
        memcpy(pf->uuid, packet->uuid, UUID_T_LENGTH);
        pf->next = buffer->hash_table[bucket];
        buffer->hash_table[bucket] = pf;
    }
    
    pf->total_fragments = packet->total_fragments;
    pf->wan_idx = packet->wan_idx;
    pf->timestamp = current_time;
    pf->fragments = NULL;
    
    // Build and store each fragment (complete IP+UDP packet)
    uint8_t fragment_buffer[MAX_PKT];
    
    for (int i = 0; i < packet->total_fragments; i++) {
        int fragment_len;
        if (build_fragment_packet(packet, i, src_ip, dst_ip,
                                 fragment_buffer, &fragment_len) != 0) {
            continue;
        }
        
        fragment_entry_t *fe = malloc(sizeof(fragment_entry_t));
        if (!fe) {
            continue;
        }
        
        fe->fragment_data = malloc(fragment_len);
        if (!fe->fragment_data) {
            free(fe);
            continue;
        }
        
        memcpy(fe->fragment_data, fragment_buffer, fragment_len);
        fe->fragment_len = fragment_len;
        fe->fragment_seq = i;
        fe->timestamp = current_time;
        
        fe->next = pf->fragments;
        pf->fragments = fe;
    }
    
    pthread_mutex_unlock(&buffer->mutex);
    
    return 0;
}

int get_fragment(fragment_buffer_t *buffer, const uuid_t uuid, int fragment_seq,
                 uint8_t *out_buffer, int *out_len, int *wan_idx) {
    if (!buffer || !uuid || !out_buffer || !out_len || fragment_seq < 0) {
        return -1;
    }
    
    pthread_mutex_lock(&buffer->mutex);
    
    uint32_t bucket = uuid_hash(uuid);
    packet_fragments_t *pf = buffer->hash_table[bucket];
    
    while (pf) {
        if (uuid_equal(pf->uuid, uuid)) {
            fragment_entry_t *fe = pf->fragments;
            while (fe) {
                if (fe->fragment_seq == fragment_seq) {
                    if (fe->fragment_len > *out_len) {
                        pthread_mutex_unlock(&buffer->mutex);
                        return -1;
                    }
                    
                    memcpy(out_buffer, fe->fragment_data, fe->fragment_len);
                    *out_len = fe->fragment_len;
                    if (wan_idx) {
                        *wan_idx = pf->wan_idx;
                    }
                    pthread_mutex_unlock(&buffer->mutex);
                    return 0;
                }
                fe = fe->next;
            }
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
        pf = pf->next;
    }
    
    pthread_mutex_unlock(&buffer->mutex);
    return -1;
}

void fragment_buffer_cleanup(fragment_buffer_t *buffer, uint64_t max_age_ms) {
    if (!buffer) {
        return;
    }
    
    pthread_mutex_lock(&buffer->mutex);
    
    uint64_t current_time = get_milliseconds();
    
    for (int i = 0; i < FRAGMENT_BUFFER_HASH_SIZE; i++) {
        packet_fragments_t **ppf = &buffer->hash_table[i];
        while (*ppf) {
            packet_fragments_t *pf = *ppf;
            
            if (current_time - pf->timestamp > max_age_ms) {
                *ppf = pf->next;
                
                fragment_entry_t *fe = pf->fragments;
                while (fe) {
                    fragment_entry_t *next_fe = fe->next;
                    free(fe->fragment_data);
                    free(fe);
                    fe = next_fe;
                }
                
                free(pf);
            } else {
                ppf = &pf->next;
            }
        }
    }
    
    pthread_mutex_unlock(&buffer->mutex);
}

// ===== Thread Pool Implementation =====

static void* thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    uint8_t fragment_buffer[MAX_PKT];
    
    while (pool->running) {
        packet_item_t *packet = packet_queue_pop(pool->queue);
        
        if (!packet) {
            break;
        }
        
        uint32_t flow_hash = calc_flow_hash(packet->uuid);
        
        if (pool->enable_fragmentation && packet->len > CHUNK_SIZE) {
            // Extract IP addresses from original packet
            struct iphdr *orig_ip = (struct iphdr *)packet->data;
            uint32_t src_ip = ntohl(orig_ip->saddr);
            uint32_t dst_ip = ntohl(orig_ip->daddr);
            
            printf("[Thread %lu] Fragmenting packet:\n", pthread_self());
            printf("  UUID: ");
            for (int i = 0; i < 8; i++) printf("%02x", packet->uuid[i]);
            printf("...\n");
            printf("  Flow: %08X | Size: %d bytes | Fragments: %d\n",
                   flow_hash, packet->len, packet->total_fragments);
            printf("  Src IP: %u.%u.%u.%u, Dst IP: %u.%u.%u.%u\n",
                   (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                   (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                   (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                   (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
            
            // Store fragments in buffer
            if (pool->fragment_buffer) {
                if (store_packet_fragments(pool->fragment_buffer, packet,
                                          src_ip, dst_ip) == 0) {
                    printf("  [BUFFER] Stored %d fragments\n",
                           packet->total_fragments);
                }
                
                uint64_t current_time = get_milliseconds();
                if (current_time - pool->fragment_buffer->last_cleanup_ms > 
                    pool->fragment_buffer->cleanup_interval_ms) {
                    fragment_buffer_cleanup(pool->fragment_buffer, 
                                          FRAGMENT_BUFFER_MAX_AGE_MS);
                    pool->fragment_buffer->last_cleanup_ms = current_time;
                }
            }
            
            // Send each fragment via different WAN
            for (int i = 0; i < packet->total_fragments; i++) {
                int fragment_len;
                
                if (build_fragment_packet(packet, i, src_ip, dst_ip,
                                        fragment_buffer, &fragment_len) == 0) {
                    
                    pthread_mutex_lock(pool->rr_lock);
                    int fragment_wan_idx = (*pool->rr_idx)++ % pool->nwan;
                    pthread_mutex_unlock(pool->rr_lock);
                    
                    if (pool->send_callback) {
                        pool->send_callback(fragment_buffer, fragment_len, 
                                          fragment_wan_idx, packet->uuid);
                    }
                    
                    printf("  [Fragment %d/%d] Sent %d bytes (IP+UDP+payload) to WAN[%d]\n",
                           i + 1, packet->total_fragments, fragment_len, fragment_wan_idx);
                    
                    usleep(500);
                }
            }
            
            printf("  [COMPLETE] All fragments sent\n\n");
            
        } else {
            if (pool->send_callback) {
                pool->send_callback(packet->data, packet->len, 
                                  packet->wan_idx, packet->uuid);
            }
            
            printf("[Thread %lu] Sent packet (no fragmentation): len=%d, wan=%d\n",
                   pthread_self(), packet->len, packet->wan_idx);
        }
        
        free(packet);
    }
    
    return NULL;
}

thread_pool_t* thread_pool_create(int num_threads, int queue_max_size,
                                   send_wan_callback_t callback,
                                   int enable_fragmentation,
                                   pthread_mutex_t *rr_lock,
                                   int *rr_idx,
                                   int nwan) {
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (!pool) {
        return NULL;
    }
    
    pool->num_threads = num_threads;
    pool->send_callback = callback;
    pool->running = 1;
    pool->enable_fragmentation = enable_fragmentation;
    pool->rr_lock = rr_lock;
    pool->rr_idx = rr_idx;
    pool->nwan = nwan;
    
    pool->fragment_buffer = fragment_buffer_create();
    if (!pool->fragment_buffer) {
        fprintf(stderr, "[Thread Pool] Warning: Failed to create fragment buffer\n");
    }
    
    pool->queue = malloc(sizeof(packet_queue_t));
    if (!pool->queue) {
        if (pool->fragment_buffer) {
            fragment_buffer_destroy(pool->fragment_buffer);
        }
        free(pool);
        return NULL;
    }
    packet_queue_init(pool->queue, queue_max_size);
    
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        packet_queue_destroy(pool->queue);
        free(pool->queue);
        if (pool->fragment_buffer) {
            fragment_buffer_destroy(pool->fragment_buffer);
        }
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
    
    if (pool->fragment_buffer) {
        fragment_buffer_destroy(pool->fragment_buffer);
    }
    
    if (pool->threads) {
        free(pool->threads);
    }
    
    free(pool);
}