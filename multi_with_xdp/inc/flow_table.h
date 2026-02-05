#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>
#include <pthread.h>

#define FLOW_TABLE_SIZE 1048576
#define FLOW_TIMEOUT_SEC 120

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
    uint64_t last_seen;
    int valid;
    struct flow_entry *next;
};

struct flow_table {
    struct flow_entry *buckets[FLOW_TABLE_SIZE];
    pthread_mutex_t locks[FLOW_TABLE_SIZE];
    uint32_t window_size;
    int wan_count;
};

void flow_table_init(struct flow_table *ft, uint32_t window_size, int wan_count);
void flow_table_cleanup(struct flow_table *ft);

int flow_table_get_wan(struct flow_table *ft,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint32_t pkt_len);

void flow_table_gc(struct flow_table *ft);

void flow_table_add_bytes(struct flow_table *ft,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol, uint32_t extra_bytes);

#endif
