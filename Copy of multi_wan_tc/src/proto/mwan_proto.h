#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

/* ================================================================ */
/* ==================== PROTOCOL CONSTANTS ======================== */
/* ================================================================ */

#define MWAN_ETHERTYPE       0x88B5  /* IEEE 802 Local Experimental */
#define MWAN_NE_TUNNEL_MTU   1418    /* ne_tunnel L3 MTU */
#define MWAN_HDR_SIZE        8       /* sizeof(mwan_hdr_t) */
#define MWAN_MAX_CHUNK       (MWAN_NE_TUNNEL_MTU - MWAN_HDR_SIZE) /* 1410 */
#define MWAN_FRAG_THRESHOLD  1400    /* IP packets <= this: no fragment */
#define MWAN_MAX_FRAGS       2       /* ceil(1500/1410) = 2 max */

/* ================================================================ */
/* ==================== WIRE HEADER =============================== */
/* ================================================================ */

/*
 * Wire format on ne_tunnel:
 *   [Eth header 14][mwan_hdr 8][original IP data chunk <= 1410]
 *    etype=0x88B5
 */
typedef struct __attribute__((packed)) {
    uint32_t seq;           /* Global sequence number (for reorder) */
    uint8_t  frag_idx;      /* Fragment index within packet (0-based) */
    uint8_t  frag_count;    /* Total fragments (1 = no fragmentation) */
    uint16_t total_len;     /* Original IP packet total length */
} mwan_hdr_t;

/* ================================================================ */
/* ==================== FRAGMENT API ============================== */
/* ================================================================ */

/* Output of mwan_fragment(): one fragment ready to send */
typedef struct {
    const uint8_t *ip_chunk;    /* Pointer into original IP data */
    uint16_t       chunk_len;   /* Length of this chunk */
    mwan_hdr_t     hdr;         /* Pre-filled mwan header */
} mwan_frag_t;

/*
 * Fragment an IP packet.
 *
 * @param ip_data    Pointer to original IP packet (after Ethernet header)
 * @param ip_len     Length of original IP packet
 * @param seq        Sequence number assigned to this packet
 * @param out_frags  Output array (caller provides, size >= MWAN_MAX_FRAGS)
 * @return           Number of fragments (1 or 2), or -1 on error
 */
int mwan_fragment(const uint8_t *ip_data, uint16_t ip_len,
                  uint32_t seq, mwan_frag_t *out_frags);

/* ================================================================ */
/* ==================== REASSEMBLY API ============================ */
/* ================================================================ */

#define REASM_TABLE_SIZE  256
#define REASM_TIMEOUT_NS  (50ULL * 1000000ULL)  /* 50ms in nanoseconds */

typedef struct {
    uint32_t seq;
    uint16_t total_len;
    uint8_t  frag_count;
    uint8_t  received_mask;     /* Bitmask: which frag_idx received */
    uint64_t timestamp_ns;      /* When first fragment arrived */
    uint8_t  data[1500];        /* Reassembled IP packet buffer */
    int      valid;
} reasm_entry_t;

typedef struct {
    reasm_entry_t entries[REASM_TABLE_SIZE];
} reasm_table_t;

/* Initialize reassembly table (zero it) */
void reasm_table_init(reasm_table_t *t);

/*
 * Insert a fragment into the reassembly table.
 *
 * @param t          Reassembly table (per-worker, no lock needed)
 * @param hdr        Parsed mwan_hdr from the received fragment
 * @param chunk      Fragment payload data
 * @param chunk_len  Fragment payload length
 * @param out_data   If reassembly complete: pointer set to t->entries[].data
 * @param out_len    If reassembly complete: set to total_len
 * @return           1 if packet complete (out_data/out_len set),
 *                   0 if still waiting for fragments,
 *                  -1 on error
 */
int reasm_table_insert(reasm_table_t *t,
                       const mwan_hdr_t *hdr,
                       const uint8_t *chunk, uint16_t chunk_len,
                       uint8_t **out_data, uint16_t *out_len);

/* Expire stale entries older than REASM_TIMEOUT_NS */
void reasm_table_expire(reasm_table_t *t, uint64_t now_ns);

/* ================================================================ */
/* ==================== REORDER API =============================== */
/* ================================================================ */

#define REORDER_WINDOW     1024
#define REORDER_TIMEOUT_NS (10ULL * 1000000ULL)  /* 10ms in nanoseconds */

typedef struct {
    _Atomic int state;          /* 0=empty, 1=ready */
    uint16_t    len;            /* IP packet length */
    uint8_t     data[1500];     /* IP packet data */
    uint64_t    insert_time_ns; /* When inserted (for timeout) */
} reorder_slot_t;

typedef struct {
    _Atomic uint32_t expected_seq;
    reorder_slot_t   slots[REORDER_WINDOW];

    /* TX socket + destination info for output */
    int              tx_fd;
    int              local_ifindex;
    uint8_t          local_src_mac[6];
    uint8_t          lan_dst_mac[6];

    volatile int    *running;
} reorder_ctx_t;

/* Initialize reorder context */
void reorder_init(reorder_ctx_t *ctx);

/*
 * Insert a reassembled packet into the reorder buffer.
 * Called by inbound workers (multi-producer).
 *
 * @param ctx      Reorder context (shared)
 * @param seq      Packet sequence number
 * @param ip_data  Reassembled IP packet
 * @param ip_len   IP packet length
 */
void reorder_insert(reorder_ctx_t *ctx, uint32_t seq,
                    const uint8_t *ip_data, uint16_t ip_len);

/*
 * Output thread main loop.
 * Reads from reorder buffer in sequence, sends to local_if.
 * Single-consumer.
 *
 * @param ctx  Reorder context
 */
void reorder_output_loop(reorder_ctx_t *ctx);

/* ================================================================ */
/* ==================== UTILITY =================================== */
/* ================================================================ */

/* Get current time in nanoseconds (monotonic clock) */
uint64_t mwan_now_ns(void);

#endif /* MWAN_PROTO_H */
