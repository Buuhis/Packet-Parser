#ifndef PKT_QUEUE_H
#define PKT_QUEUE_H

#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

/*
 * SPSC (Single-Producer Single-Consumer) lock-free ring queue.
 *
 * Producer = RX thread (pushes captured packets)
 * Consumer = TX worker (pops packets, fragments, sends to tunnel)
 *
 * No locks, no CAS — only memory ordering (acquire/release).
 * Capacity must be power of 2 for fast modulo via bitmask.
 */

#define PKT_QUEUE_CAPACITY 65536        /* Improved cache locality (was 524288) */
#define PKT_QUEUE_MASK     (PKT_QUEUE_CAPACITY - 1)
#define PKT_SLOT_DATA_SIZE 1522        /* Small better for typical MTU, saves memory vs 2048 */

struct pkt_slot {
    uint8_t  data[PKT_SLOT_DATA_SIZE];
    uint32_t len;
    uint32_t hash;
};

struct pkt_queue {
    /* Producer side (RX thread writes) */
    _Atomic uint32_t write_idx;
    char _pad_w[60]; /* avoid false sharing */

    /* Consumer side (TX worker writes) */
    _Atomic uint32_t read_idx;
    char _pad_r[60];

    struct pkt_slot slots[PKT_QUEUE_CAPACITY];
};

static inline void pkt_queue_init(struct pkt_queue *q)
{
    atomic_store_explicit(&q->write_idx, 0, memory_order_relaxed);
    atomic_store_explicit(&q->read_idx,  0, memory_order_relaxed);
}

/*
 * Producer: push one packet into the queue.
 * Returns 0 on success, -1 if queue is full.
 */
static inline int pkt_queue_push(struct pkt_queue *q,
                                  const uint8_t *data, uint32_t len, uint32_t hash)
{
    uint32_t w = atomic_load_explicit(&q->write_idx, memory_order_relaxed);
    uint32_t next_w = (w + 1) & PKT_QUEUE_MASK;

    /* Check if full (next write position == read position) */
    if (__builtin_expect(next_w == atomic_load_explicit(&q->read_idx, memory_order_acquire), 0))
        return -1;

    struct pkt_slot *slot = &q->slots[w];
    if (__builtin_expect(len > PKT_SLOT_DATA_SIZE, 0)) len = PKT_SLOT_DATA_SIZE;
    memcpy(slot->data, data, len);
    slot->len = len;
    slot->hash = hash;

    /* Release: ensure memcpy is visible before advancing write_idx */
    atomic_store_explicit(&q->write_idx, next_w, memory_order_release);
    return 0;
}

/*
 * Consumer: get current write position (snapshot).
 * Used to batch-read multiple slots without repeated atomic loads.
 */
static inline uint32_t pkt_queue_write_pos(const struct pkt_queue *q)
{
    return atomic_load_explicit(&q->write_idx, memory_order_acquire);
}

/*
 * Consumer: get pointer to slot at given read position.
 * Caller must ensure read_pos != write_pos (not empty).
 */
static inline struct pkt_slot *pkt_queue_slot_at(struct pkt_queue *q,
                                                  uint32_t read_pos)
{
    return &q->slots[read_pos & PKT_QUEUE_MASK];
}

/*
 * Consumer: advance read index after processing slots.
 * Call AFTER sendmmsg() completes so slot data remains valid during send.
 */
static inline void pkt_queue_consume_to(struct pkt_queue *q, uint32_t new_read)
{
    atomic_store_explicit(&q->read_idx, new_read, memory_order_release);
}

#endif /* PKT_QUEUE_H */
