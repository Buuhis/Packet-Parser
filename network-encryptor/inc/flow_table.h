#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "config.h"
#include <stdint.h>
#include <pthread.h>

#define FLOW_TABLE_SIZE 16384
#define FLOW_TIMEOUT_SEC 60

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_entry {
    struct flow_key key;
    uint32_t byte_count;
    int current_wan;
    int wrr_slot;
    uint64_t last_seen;
    int valid;

    uint8_t ip_only_key;
    uint8_t profile_wan_pool;
    struct flow_entry *next;
};

struct flow_table {
    struct flow_entry *buckets[FLOW_TABLE_SIZE];
    pthread_mutex_t locks[FLOW_TABLE_SIZE];
    int wan_count;
    uint32_t wan_window_sizes[MAX_INTERFACES]; 
};

void flow_table_init(struct flow_table *ft, const uint32_t *wan_window_sizes, int wan_count);
void flow_table_cleanup(struct flow_table *ft);

int flow_table_get_wan(struct flow_table *ft,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint32_t pkt_len);


int flow_table_get_wan_profile(struct flow_table *ft,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t protocol, uint32_t pkt_len,
                                const int *allowed_wans, int allowed_count,
                                const int *allowed_weights);

void flow_table_gc(struct flow_table *ft);

void flow_table_add_bytes(struct flow_table *ft,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol, uint32_t extra_bytes);

#endif