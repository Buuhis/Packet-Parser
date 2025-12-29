#include "packet_reassembly.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

// ===== Utility Functions =====

static uint32_t uuid_hash_reassembly(const uuid_t uuid) {
    uint32_t hash = 0;
    for (int i = 0; i < UUID_T_LENGTH; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash % 256;
}

static int uuid_equal_reassembly(const uuid_t uuid1, const uuid_t uuid2) {
    return memcmp(uuid1, uuid2, UUID_T_LENGTH) == 0;
}

static uint64_t get_min_rtt(reassembly_manager_t *mgr) {
    uint64_t min = UINT64_MAX;
    for (int i = 0; i < mgr->nwan; i++) {
        if (mgr->wan_rtt[i].min_rtt > 0 && mgr->wan_rtt[i].min_rtt < min) {
            min = mgr->wan_rtt[i].min_rtt;
        }
    }
    return (min == UINT64_MAX) ? 100 : min;
}

// ===== RTT Management =====

void reassembly_update_rtt(reassembly_manager_t *mgr, int wan_idx, uint64_t rtt_ms) {
    if (!mgr || wan_idx < 0 || wan_idx >= mgr->nwan) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    wan_rtt_stats_t *stats = &mgr->wan_rtt[wan_idx];
    
    stats->rtt_samples[stats->sample_index] = rtt_ms;
    stats->sample_index = (stats->sample_index + 1) % RTT_SAMPLES;
    
    if (stats->sample_count < RTT_SAMPLES) {
        stats->sample_count++;
    }
    
    uint64_t sum = 0;
    uint64_t min = UINT64_MAX;
    
    for (int i = 0; i < stats->sample_count; i++) {
        sum += stats->rtt_samples[i];
        if (stats->rtt_samples[i] < min) {
            min = stats->rtt_samples[i];
        }
    }
    
    stats->min_rtt = min;
    stats->avg_rtt = sum / stats->sample_count;
    stats->last_update = get_milliseconds();
    
    pthread_mutex_unlock(&mgr->mutex);
    
    printf("[RTT] WAN[%d] updated: min=%lums, avg=%lums\n", 
           wan_idx, (unsigned long)min, (unsigned long)(sum / stats->sample_count));
}

// ===== Reassembly Entry Management =====

static reassembly_entry_t* find_or_create_entry(
    reassembly_manager_t *mgr,
    const uuid_t uuid,
    int *created
) {
    uint32_t bucket = uuid_hash_reassembly(uuid);
    reassembly_entry_t *entry = mgr->hash_table[bucket];
    
    while (entry) {
        if (uuid_equal_reassembly(entry->uuid, uuid)) {
            *created = 0;
            return entry;
        }
        entry = entry->next;
    }
    
    entry = calloc(1, sizeof(reassembly_entry_t));
    if (!entry) {
        return NULL;
    }
    
    memcpy(entry->uuid, uuid, UUID_T_LENGTH);
    entry->state = REASSEMBLY_STATE_RECEIVING;
    entry->first_fragment_time = get_milliseconds();
    entry->last_activity_time = entry->first_fragment_time;
    entry->request_count = 0;
    entry->last_request_time = 0;
    
    entry->next = mgr->hash_table[bucket];
    mgr->hash_table[bucket] = entry;
    
    *created = 1;
    return entry;
}

static void free_entry(reassembly_entry_t *entry) {
    if (!entry) {
        return;
    }
    
    for (int i = 0; i < entry->total_fragments; i++) {
        if (entry->fragments[i].data) {
            free(entry->fragments[i].data);
        }
    }
    free(entry);
}

static void remove_entry(reassembly_manager_t *mgr, const uuid_t uuid) {
    uint32_t bucket = uuid_hash_reassembly(uuid);
    reassembly_entry_t **pp = &mgr->hash_table[bucket];
    
    while (*pp) {
        if (uuid_equal_reassembly((*pp)->uuid, uuid)) {
            reassembly_entry_t *to_free = *pp;
            *pp = (*pp)->next;
            free_entry(to_free);
            return;
        }
        pp = &(*pp)->next;
    }
}

// ===== Fragment Processing =====

static int parse_fragment_header(
    const uint8_t *fragment_pkt,
    int fragment_len,
    uuid_t uuid,
    uint32_t *seq,
    uint32_t *total,
    uint32_t *data_len,
    const uint8_t **data_ptr
) {
    if (fragment_len < FRAGMENT_HEADER_SIZE) {
        return -1;
    }
    
    const uint8_t *ptr = fragment_pkt;
    
    // Magic number
    uint16_t magic;
    memcpy(&magic, ptr, 2);
    magic = ntohs(magic);
    if (magic != FRAGMENT_MAGIC) {
        return -1;
    }
    ptr += 2;
    
    // UUID
    memcpy(uuid, ptr, UUID_T_LENGTH);
    ptr += UUID_T_LENGTH;
    
    // Sequence, total, data_len
    memcpy(seq, ptr, 4);
    *seq = ntohl(*seq);
    ptr += 4;
    
    memcpy(total, ptr, 4);
    *total = ntohl(*total);
    ptr += 4;
    
    memcpy(data_len, ptr, 4);
    *data_len = ntohl(*data_len);
    ptr += 4;
    
    *data_ptr = ptr;
    
    if (*seq >= *total || *total > MAX_FRAGMENTS_PER_PACKET) {
        return -1;
    }
    
    if (fragment_len != FRAGMENT_HEADER_SIZE + *data_len) {
        return -1;
    }
    
    return 0;
}

static int reassemble_packet(reassembly_entry_t *entry, uint8_t **out_pkt, int *out_len) {
    int total_size = 0;
    for (int i = 0; i < entry->total_fragments; i++) {
        if (!entry->fragments[i].received) {
            return -1;
        }
        total_size += entry->fragments[i].len;
    }
    
    uint8_t *packet = malloc(total_size);
    if (!packet) {
        return -1;
    }
    
    uint8_t *ptr = packet;
    for (int i = 0; i < entry->total_fragments; i++) {
        memcpy(ptr, entry->fragments[i].data, entry->fragments[i].len);
        ptr += entry->fragments[i].len;
    }
    
    *out_pkt = packet;
    *out_len = total_size;
    
    return 0;
}

// ===== GET ALL MISSING FRAGMENTS (FIX) =====
static int get_all_missing_fragments(reassembly_entry_t *entry, 
                                     int *missing_list, 
                                     int max_missing) {
    int count = 0;
    
    for (int i = 0; i < entry->total_fragments && count < max_missing; i++) {
        if (!entry->fragments[i].received) {
            missing_list[count++] = i;
        }
    }
    
    return count;
}

// ===== Main Processing Function (FIXED) =====

int reassembly_process_fragment(
    reassembly_manager_t *mgr,
    const uint8_t *fragment_pkt,
    int fragment_len,
    int wan_idx
) {
    if (!mgr || !fragment_pkt || fragment_len < FRAGMENT_HEADER_SIZE) {
        return -1;
    }
    
    uuid_t uuid;
    uint32_t seq, total, data_len;
    const uint8_t *data_ptr;
    
    if (parse_fragment_header(fragment_pkt, fragment_len, uuid, 
                              &seq, &total, &data_len, &data_ptr) != 0) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    int created;
    reassembly_entry_t *entry = find_or_create_entry(mgr, uuid, &created);
    if (!entry) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (created) {
        entry->total_fragments = total;
        entry->wan_idx = wan_idx;
        printf("[REASSEMBLY] New packet UUID ");
        for (int i = 0; i < 8; i++) printf("%02x", uuid[i]);
        printf("... total_fragments=%d\n", total);
    }
    
    if (entry->total_fragments != (int)total) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    // Store fragment
    if (!entry->fragments[seq].received) {
        entry->fragments[seq].data = malloc(data_len);
        if (!entry->fragments[seq].data) {
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
        
        memcpy(entry->fragments[seq].data, data_ptr, data_len);
        entry->fragments[seq].len = data_len;
        entry->fragments[seq].timestamp = get_milliseconds();
        entry->fragments[seq].received = 1;
        entry->received_count++;
        entry->last_activity_time = entry->fragments[seq].timestamp;
        
        printf("[REASSEMBLY] Received fragment %d/%d from WAN[%d] (total: %d/%d)\n", 
               seq + 1, total, wan_idx, entry->received_count, total);
    }
    
    // ===== PHẦN A: Check complete =====
    if (entry->received_count == entry->total_fragments) {
        uint8_t *reassembled_pkt;
        int reassembled_len;
        
        if (reassemble_packet(entry, &reassembled_pkt, &reassembled_len) == 0) {
            printf("[REASSEMBLY] ✓ Packet completed (%d bytes), sending to local\n", 
                   reassembled_len);
            
            entry->state = REASSEMBLY_STATE_COMPLETED;
            mgr->total_packets_completed++;
            
            pthread_mutex_unlock(&mgr->mutex);
            
            if (mgr->send_to_local_callback) {
                mgr->send_to_local_callback(reassembled_pkt, reassembled_len);
            }
            
            free(reassembled_pkt);
            
            pthread_mutex_lock(&mgr->mutex);
            remove_entry(mgr, uuid);
            pthread_mutex_unlock(&mgr->mutex);
            
            return 1;
        }
    }
    
    // ===== PHẦN B: Handle missing fragments (FIXED) =====
    int missing_list[MAX_FRAGMENTS_PER_PACKET];
    int missing_count = get_all_missing_fragments(entry, missing_list, 
                                                   MAX_FRAGMENTS_PER_PACKET);
    
    if (missing_count > 0) {
        uint64_t current_time = get_milliseconds();
        uint64_t elapsed = current_time - entry->first_fragment_time;
        uint64_t min_rtt = get_min_rtt(mgr);
        uint64_t half_rtt = min_rtt / 2;
        
        // STATE 1: RECEIVING - Wait for half RTT
        if (entry->state == REASSEMBLY_STATE_RECEIVING) {
            if (elapsed >= half_rtt) {
                printf("[REASSEMBLY] Missing %d fragments after %.1fms, requesting...\n",
                       missing_count, (double)half_rtt);
                
                // ===== REQUEST ALL MISSING FRAGMENTS =====
                for (int i = 0; i < missing_count; i++) {
                    int missing_seq = missing_list[i];
                    
                    if (mgr->request_retransmission_callback) {
                        printf("[REASSEMBLY] → Request fragment %d\n", missing_seq);
                        mgr->request_retransmission_callback(uuid, missing_seq, 
                                                            entry->wan_idx);
                        mgr->total_retrans_requests++;
                    }
                    
                    usleep(1000);  // 1ms delay between requests
                }
                
                entry->state = REASSEMBLY_STATE_WAITING_RETRANS;
                entry->wait_until = current_time + RETRANSMIT_REQUEST_TIMEOUT_MS;
                entry->request_count = 1;
                entry->last_request_time = current_time;
            } else {
                printf("[REASSEMBLY] Missing %d fragments, waiting (%.1fms left)\n",
                       missing_count, (double)(half_rtt - elapsed));
            }
        }
        
        // STATE 2: WAITING_RETRANS - Handle timeout and re-request
        else if (entry->state == REASSEMBLY_STATE_WAITING_RETRANS) {
            uint64_t time_since_request = current_time - entry->last_request_time;
            
            // Re-request if no progress
            if (time_since_request > min_rtt * 2 && 
                entry->request_count < MAX_RETRANS_ATTEMPTS) {
                
                printf("[REASSEMBLY] Re-requesting %d fragments (attempt %d/%d)\n",
                       missing_count, entry->request_count + 1, MAX_RETRANS_ATTEMPTS);
                
                for (int i = 0; i < missing_count; i++) {
                    if (mgr->request_retransmission_callback) {
                        mgr->request_retransmission_callback(uuid, missing_list[i], 
                                                            entry->wan_idx);
                        mgr->total_retrans_requests++;
                    }
                    usleep(1000);
                }
                
                entry->request_count++;
                entry->last_request_time = current_time;
                entry->wait_until = current_time + RETRANSMIT_REQUEST_TIMEOUT_MS;
            }
            
            // Timeout
            if (current_time >= entry->wait_until) {
                printf("[REASSEMBLY] ✗ Timeout after %d attempts, missing %d fragments\n",
                       entry->request_count, missing_count);
                
                entry->state = REASSEMBLY_STATE_TIMEOUT;
                mgr->total_packets_timeout++;
                
                remove_entry(mgr, uuid);
                pthread_mutex_unlock(&mgr->mutex);
                return -1;
            }
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

// ===== Periodic Maintenance =====

void reassembly_periodic_check(reassembly_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    uint64_t current_time = get_milliseconds();
    
    for (int i = 0; i < 256; i++) {
        reassembly_entry_t **pp = &mgr->hash_table[i];
        
        while (*pp) {
            reassembly_entry_t *entry = *pp;
            
            // Age-based cleanup (30s)
            if (current_time - entry->first_fragment_time > 30000) {
                printf("[REASSEMBLY] ✗ Packet aged out (>30s)\n");
                mgr->total_packets_timeout++;
                
                *pp = entry->next;
                free_entry(entry);
                continue;
            }
            
            pp = &(*pp)->next;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
}

// ===== Manager Lifecycle =====

reassembly_manager_t* reassembly_manager_create(
    int nwan,
    void (*send_to_local_callback)(uint8_t *pkt, int len),
    int (*request_retransmission_callback)(const uuid_t uuid, int fragment_seq, int wan_idx)
) {
    reassembly_manager_t *mgr = calloc(1, sizeof(reassembly_manager_t));
    if (!mgr) {
        return NULL;
    }
    
    mgr->nwan = nwan;
    mgr->send_to_local_callback = send_to_local_callback;
    mgr->request_retransmission_callback = request_retransmission_callback;
    
    pthread_mutex_init(&mgr->mutex, NULL);
    
    for (int i = 0; i < nwan && i < MAX_WAN; i++) {
        mgr->wan_rtt[i].min_rtt = 100;
        mgr->wan_rtt[i].avg_rtt = 100;
    }
    
    printf("[REASSEMBLY] Manager created for %d WAN interfaces\n", nwan);
    
    return mgr;
}

void reassembly_manager_destroy(reassembly_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < 256; i++) {
        reassembly_entry_t *entry = mgr->hash_table[i];
        while (entry) {
            reassembly_entry_t *next = entry->next;
            free_entry(entry);
            entry = next;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    free(mgr);
}

void reassembly_print_stats(reassembly_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    printf("\n========== REASSEMBLY STATISTICS ==========\n");
    printf("Total packets received:   %lu\n", (unsigned long)mgr->total_packets_received);
    printf("Total packets completed:  %lu\n", (unsigned long)mgr->total_packets_completed);
    printf("Total packets timeout:    %lu\n", (unsigned long)mgr->total_packets_timeout);
    printf("Total retrans requests:   %lu\n", (unsigned long)mgr->total_retrans_requests);
    
    if (mgr->total_packets_completed + mgr->total_packets_timeout > 0) {
        double success_rate = (double)mgr->total_packets_completed / 
                             (mgr->total_packets_completed + mgr->total_packets_timeout) * 100.0;
        printf("Success rate:             %.2f%%\n", success_rate);
    }
    
    printf("\nRTT Statistics:\n");
    for (int i = 0; i < mgr->nwan; i++) {
        wan_rtt_stats_t *stats = &mgr->wan_rtt[i];
        if (stats->sample_count > 0) {
            printf("  WAN[%d]: min=%lums, avg=%lums, samples=%d\n",
                   i, (unsigned long)stats->min_rtt, 
                   (unsigned long)stats->avg_rtt,
                   stats->sample_count);
        }
    }
    printf("==========================================\n\n");
    
    pthread_mutex_unlock(&mgr->mutex);
}