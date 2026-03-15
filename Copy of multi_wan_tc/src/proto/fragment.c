#define _POSIX_C_SOURCE 200112L
#include "fragment.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

static atomic_uint_fast32_t g_pkt_id_counter = 0;

uint16_t frag_next_pkt_id(void) {
    return (uint16_t)(atomic_fetch_add(&g_pkt_id_counter, 1) & 0xFFFF);
}

void frag_table_init(struct frag_table *ft) {
    memset(ft, 0, sizeof(*ft));
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        pthread_spin_init(&ft->entries[i].lock, PTHREAD_PROCESS_PRIVATE);
    }
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void frag_table_gc(struct frag_table *ft) {
    uint64_t now = get_time_ns();
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        struct frag_entry *entry = &ft->entries[i];
        if (entry->has_frag) {
            pthread_spin_lock(&entry->lock);
            if (entry->has_frag && (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
                entry->has_frag = 0;
            }
            pthread_spin_unlock(&entry->lock);
        }
    }
}

int frag_store_or_reassemble(struct frag_table *ft,
                              const uint8_t *data, uint32_t data_len,
                              uint16_t pkt_id, uint8_t frag_index,
                              uint8_t *out_buf, uint32_t *out_len)
{
    int idx = pkt_id & (FRAG_TABLE_SIZE - 1);
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    pthread_spin_lock(&entry->lock);

    /* Timeout: discard stale fragment */
    if (entry->has_frag && (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
        entry->has_frag = 0;
    }

    if (frag_index == VXLAN_FRAG_FIRST) {
        /* Store fragment 1 (first half of raw Ethernet frame) */
        if (data_len > sizeof(entry->data)) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }
        entry->pkt_id = pkt_id;
        entry->timestamp_ns = now;
        memcpy(entry->data, data, data_len);
        entry->data_len = data_len;
        entry->has_frag = 1;
        pthread_spin_unlock(&entry->lock);
        return 0; /* stored, waiting for frag 2 */
    }

    if (frag_index == VXLAN_FRAG_LAST) {
        /* Need matching fragment 1 */
        if (!entry->has_frag || entry->pkt_id != pkt_id) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        uint32_t total = entry->data_len + data_len;
        if (total > 4096) {
            entry->has_frag = 0;
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        /* Reassemble: frag1_data + frag2_data = original Ethernet frame */
        memcpy(out_buf, entry->data, entry->data_len);
        memcpy(out_buf + entry->data_len, data, data_len);
        *out_len = total;
        entry->has_frag = 0;
        pthread_spin_unlock(&entry->lock);
        return 1; /* successfully reassembled */
    }

    pthread_spin_unlock(&entry->lock);
    return -1;
}
