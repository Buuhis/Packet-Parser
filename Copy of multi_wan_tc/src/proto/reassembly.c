#include "mwan_proto.h"

#include <string.h>
#include <time.h>

uint64_t mwan_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void reasm_table_init(reasm_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

int reasm_table_insert(reasm_table_t *t,
                       const mwan_hdr_t *hdr,
                       const uint8_t *chunk, uint16_t chunk_len,
                       uint8_t **out_data, uint16_t *out_len)
{
    if (!t || !hdr || !chunk || !out_data || !out_len)
        return -1;

    if (hdr->frag_idx >= hdr->frag_count || hdr->frag_count > MWAN_MAX_FRAGS)
        return -1;

    uint32_t idx = hdr->seq % REASM_TABLE_SIZE;
    reasm_entry_t *e = &t->entries[idx];

    /* If slot is occupied by a different seq, evict it */
    if (e->valid && e->seq != hdr->seq) {
        e->valid = 0;
        e->received_mask = 0;
    }

    /* Initialize entry on first fragment */
    if (!e->valid) {
        memset(e, 0, sizeof(*e));
        e->seq          = hdr->seq;
        e->total_len    = hdr->total_len;
        e->frag_count   = hdr->frag_count;
        e->timestamp_ns = mwan_now_ns();
        e->valid        = 1;
    }

    /* Validate consistency */
    if (e->total_len != hdr->total_len || e->frag_count != hdr->frag_count)
        return -1;

    /* Check for duplicate fragment */
    uint8_t frag_bit = (uint8_t)(1 << hdr->frag_idx);
    if (e->received_mask & frag_bit)
        return 0;  /* Duplicate, still waiting */

    /* Copy chunk data to correct offset in buffer */
    uint16_t offset = (uint16_t)hdr->frag_idx * MWAN_MAX_CHUNK;
    if (offset + chunk_len > sizeof(e->data))
        return -1;  /* Overflow protection */

    memcpy(e->data + offset, chunk, chunk_len);
    e->received_mask |= frag_bit;

    /* Check if all fragments received */
    uint8_t complete_mask = (uint8_t)((1 << e->frag_count) - 1);
    if (e->received_mask == complete_mask) {
        *out_data = e->data;
        *out_len  = e->total_len;
        e->valid = 0;  /* Free the slot */
        return 1;       /* Complete! */
    }

    return 0;  /* Still waiting for more fragments */
}

void reasm_table_expire(reasm_table_t *t, uint64_t now_ns)
{
    for (int i = 0; i < REASM_TABLE_SIZE; i++) {
        reasm_entry_t *e = &t->entries[i];
        if (e->valid && (now_ns - e->timestamp_ns) > REASM_TIMEOUT_NS) {
            e->valid = 0;
            e->received_mask = 0;
        }
    }
}
