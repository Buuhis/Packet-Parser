#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "mwan_proto.h"

#define FRAG_TABLE_SIZE     65536
#define FRAG_TIMEOUT_NS     (50ULL * 1000000ULL) /* 50ms */

/* Max inner Ethernet frame that fits in one VXLAN UDP packet */
#define FRAG_INNER_MAX      (MWAN_NE_TUNNEL_MTU - VXLAN_HDR_SIZE)  /* 1410 */

struct frag_entry {
    uint16_t pkt_id;
    uint8_t  data[2048];       /* Stored fragment 1 raw data */
    uint32_t data_len;
    uint64_t timestamp_ns;
    uint8_t  has_frag;         /* 1 if fragment 1 is stored */
    pthread_spinlock_t lock;
};

struct frag_table {
    struct frag_entry entries[FRAG_TABLE_SIZE];
};

uint16_t frag_next_pkt_id(void);
void frag_table_init(struct frag_table *ft);
void frag_table_gc(struct frag_table *ft);

/* Check if raw Ethernet frame needs splitting for tunnel */
static inline int frag_need_split(uint32_t frame_len) {
    return frame_len > FRAG_INNER_MAX;
}

/*
 * Store a fragment or reassemble if both halves are present.
 * Returns:
 *   1  = successfully reassembled (out_buf/out_len filled)
 *   0  = fragment stored, waiting for counterpart
 *  -1  = error
 */
int frag_store_or_reassemble(struct frag_table *ft,
                              const uint8_t *data, uint32_t data_len,
                              uint16_t pkt_id, uint8_t frag_index,
                              uint8_t *out_buf, uint32_t *out_len);

#endif
