#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "mwan_proto.h"

#define FRAG_PLAIN_HDR_SIZE 4   /* marker(1) + pkt_id(2) + frag_index(1) */
#define FRAG_FLAG_BIT       0x80
#define FRAG_MTU            MWAN_NE_TUNNEL_MTU // 1418
#define FRAG_TABLE_SIZE     4096
#define FRAG_TIMEOUT_NS     (100ULL * 1000000ULL) // 100ms
#define FRAG_PROTOCOL       253

struct frag_entry {
    uint16_t pkt_id;
    uint8_t  data0[2048];
    uint32_t data0_len;
    uint8_t  data1[2048];
    uint32_t data1_len;
    uint8_t  eth_hdr[14];
    uint8_t  ip_hdr[60];
    int      ip_hdr_len;
    uint8_t  orig_proto;
    uint64_t timestamp_ns;
    uint8_t  has_frag0;
    uint8_t  has_frag1;
    pthread_spinlock_t lock;
};

struct frag_table {
    struct frag_entry entries[FRAG_TABLE_SIZE];
};

uint16_t frag_next_pkt_id(void);

void frag_table_init(struct frag_table *ft);

void frag_table_gc(struct frag_table *ft);

static inline int frag_need_split(uint32_t pkt_len) {
    return (pkt_len + FRAG_PLAIN_HDR_SIZE) > FRAG_MTU;
}

int frag_split(const uint8_t *pkt_data, uint32_t pkt_len,
               uint8_t *frag1, uint32_t *frag1_len,
               uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index);

int frag_defragment(uint8_t *packet, size_t pkt_len,
                    uint16_t *out_pkt_id, uint8_t *out_frag_index);

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len);

#endif
