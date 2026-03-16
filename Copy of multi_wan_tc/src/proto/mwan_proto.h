#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <stdint.h>

/* ================================================================ */
/* ==================== PROTOCOL CONSTANTS ======================== */
/* ================================================================ */

#define MWAN_ETHERTYPE 0x88B5                               /* IEEE 802 Local Experimental */

/* ---- Fragmentation Metadata (8 bytes) ---- */
#define MWAN_FRAG_NONE     0
#define MWAN_FRAG_FIRST    1
#define MWAN_FRAG_LAST     2

#define MWAN_METADATA_SIZE 8

typedef struct __attribute__((packed)) {
    uint8_t  magic;          /* 0xAE - Magic byte to identify MWAN metadata */
    uint8_t  frag_index;     /* 0=none, 1=first, 2=last */
    uint16_t pkt_id;         /* Sequence ID for reassembly */
    uint32_t reserved;       /* Padding to align to 8 bytes */
} mwan_metadata_t;

static inline void mwan_metadata_build(mwan_metadata_t *hdr, uint16_t pkt_id, uint8_t frag_index) {
    hdr->magic = 0xAE;
    hdr->frag_index = frag_index;
    hdr->pkt_id = pkt_id;
    hdr->reserved = 0;
}

static inline int mwan_metadata_read(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    const mwan_metadata_t *hdr = (const mwan_metadata_t *)buf;
    if (hdr->magic != 0xAE) return -1;
    *pkt_id = hdr->pkt_id;
    *frag_index = hdr->frag_index;
    return 0;
}

#define MWAN_NE_TUNNEL_MTU 1418                             /* ne_tunnel L3 MTU */

#endif /* MWAN_PROTO_H */
