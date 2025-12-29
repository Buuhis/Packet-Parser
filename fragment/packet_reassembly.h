#ifndef PACKET_REASSEMBLY_H
#define PACKET_REASSEMBLY_H

#include <stdint.h>
#include <pthread.h>
#include "packet_queue.h"

#define MAX_WAN 10
#define REASSEMBLY_BUFFER_SIZE 1000
#define MAX_FRAGMENTS_PER_PACKET 100
#define RTT_SAMPLES 10
#define RETRANSMIT_REQUEST_TIMEOUT_MS 5000
#define MAX_RETRANS_ATTEMPTS 3

// ===== RTT Tracking =====
typedef struct {
    uint64_t rtt_samples[RTT_SAMPLES];
    int sample_count;
    int sample_index;
    uint64_t min_rtt;
    uint64_t avg_rtt;
    uint64_t last_update;
} wan_rtt_stats_t;

// ===== Fragment Tracking =====
typedef struct fragment_slot {
    uint8_t *data;
    int len;
    uint64_t timestamp;
    int received;
} fragment_slot_t;

// ===== Packet Reassembly Entry =====
typedef struct reassembly_entry {
    uuid_t uuid;
    int total_fragments;
    int received_count;
    fragment_slot_t fragments[MAX_FRAGMENTS_PER_PACKET];
    uint64_t first_fragment_time;
    uint64_t last_activity_time;
    int wan_idx;
    
    enum {
        REASSEMBLY_STATE_RECEIVING,
        REASSEMBLY_STATE_WAITING_RETRANS,
        REASSEMBLY_STATE_COMPLETED,
        REASSEMBLY_STATE_TIMEOUT
    } state;
    
    uint64_t wait_until;
    int request_count;
    uint64_t last_request_time;
    
    struct reassembly_entry *next;
} reassembly_entry_t;

// ===== Reassembly Manager =====
typedef struct {
    reassembly_entry_t *hash_table[256];
    pthread_mutex_t mutex;
    
    wan_rtt_stats_t wan_rtt[MAX_WAN];
    int nwan;
    
    void (*send_to_local_callback)(uint8_t *pkt, int len);
    int (*request_retransmission_callback)(const uuid_t uuid, int fragment_seq, int wan_idx);
    
    uint64_t total_packets_received;
    uint64_t total_packets_completed;
    uint64_t total_packets_timeout;
    uint64_t total_retrans_requests;
    
} reassembly_manager_t;

// ===== Public Functions =====

reassembly_manager_t* reassembly_manager_create(
    int nwan,
    void (*send_to_local_callback)(uint8_t *pkt, int len),
    int (*request_retransmission_callback)(const uuid_t uuid, int fragment_seq, int wan_idx)
);

void reassembly_manager_destroy(reassembly_manager_t *mgr);

int reassembly_process_fragment(
    reassembly_manager_t *mgr,
    const uint8_t *fragment_pkt,
    int fragment_len,
    int wan_idx
);

void reassembly_update_rtt(
    reassembly_manager_t *mgr,
    int wan_idx,
    uint64_t rtt_ms
);

void reassembly_periodic_check(reassembly_manager_t *mgr);

void reassembly_print_stats(reassembly_manager_t *mgr);

#endif // PACKET_REASSEMBLY_H