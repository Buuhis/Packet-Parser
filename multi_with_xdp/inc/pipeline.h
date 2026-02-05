#ifndef PIPELINE_H
#define PIPELINE_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>

#define PKT_SLOT_DATA_SIZE  4096
#define RING_DEFAULT_SIZE   8192
#define POOL_DEFAULT_SIZE   16384

/* ================================================================
 * Packet Slot - unit of work passed between pipeline stages
 * ================================================================ */
struct pkt_slot {
    uint8_t  data[PKT_SLOT_DATA_SIZE];
    uint32_t len;
    int      wan_idx;
    int      local_idx;
    uint16_t frag_pkt_id;
    uint8_t  frag_index;
    int      is_fragment;
};

/* ================================================================
 * MPMC Ring Buffer (Dmitry Vyukov bounded queue)
 * Lock-free, supports multiple producers + multiple consumers
 * ================================================================ */
struct ring_entry {
    atomic_uint_fast32_t seq;
    uint32_t data;
};

struct mpmc_ring {
    alignas(64) atomic_uint_fast32_t head;
    alignas(64) atomic_uint_fast32_t tail;
    uint32_t capacity;
    uint32_t mask;
    struct ring_entry *entries;
};

int  mpmc_ring_init(struct mpmc_ring *ring, uint32_t capacity);
void mpmc_ring_destroy(struct mpmc_ring *ring);
int  mpmc_ring_enqueue(struct mpmc_ring *ring, uint32_t data);
int  mpmc_ring_dequeue(struct mpmc_ring *ring, uint32_t *data);
int  mpmc_ring_dequeue_batch(struct mpmc_ring *ring, uint32_t *out, int max);

/* ================================================================
 * Packet Pool - pre-allocated slots with lock-free alloc/free
 * ================================================================ */
struct pkt_pool {
    struct pkt_slot *slots;
    struct mpmc_ring free_ring;
    uint32_t capacity;
};

int  pkt_pool_init(struct pkt_pool *pool, uint32_t capacity);
void pkt_pool_destroy(struct pkt_pool *pool);
int  pkt_pool_alloc(struct pkt_pool *pool);
void pkt_pool_free(struct pkt_pool *pool, uint32_t idx);

/* ================================================================
 * Hash functions for flow distribution
 * ================================================================ */
uint32_t hash_5tuple(const uint8_t *pkt_data, uint32_t pkt_len);
uint32_t hash_ip_pair(const uint8_t *pkt_data, uint32_t pkt_len);

/* ================================================================
 * Pipeline Context
 * ================================================================ */
struct pipeline_ctx {
    struct pkt_pool pool;

    /* Outbound: LOCAL -> WAN */
    struct mpmc_ring *outbound_worker_rings;
    int num_outbound_workers;

    /* Inbound: WAN -> LOCAL */
    struct mpmc_ring *inbound_worker_rings;
    int num_inbound_workers;

    /* TX output rings */
    struct mpmc_ring *tx_wan_rings;
    int tx_wan_count;

    struct mpmc_ring *tx_local_rings;
    int tx_local_count;
};

int  pipeline_init(struct pipeline_ctx *ctx,
                   int num_outbound_workers,
                   int num_inbound_workers,
                   int wan_count, int local_count,
                   uint32_t ring_size, uint32_t pool_size);
void pipeline_destroy(struct pipeline_ctx *ctx);

/* CPU pause for spin-wait */
static inline void cpu_pause(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#else
    /* no-op */
#endif
}

#endif
