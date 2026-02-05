#include "../inc/pipeline.h"
#include <stdio.h>

/* ================================================================
 * MPMC Ring Buffer (Dmitry Vyukov bounded queue)
 * ================================================================ */

static uint32_t next_power_of_2(uint32_t v) {
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4;
    v |= v >> 8; v |= v >> 16;
    return v + 1;
}

int mpmc_ring_init(struct mpmc_ring *ring, uint32_t capacity) {
    capacity = next_power_of_2(capacity);
    ring->capacity = capacity;
    ring->mask = capacity - 1;
    atomic_store(&ring->head, 0);
    atomic_store(&ring->tail, 0);

    ring->entries = calloc(capacity, sizeof(struct ring_entry));
    if (!ring->entries) return -1;

    for (uint32_t i = 0; i < capacity; i++)
        atomic_store_explicit(&ring->entries[i].seq, i, memory_order_relaxed);

    return 0;
}

void mpmc_ring_destroy(struct mpmc_ring *ring) {
    free(ring->entries);
    ring->entries = NULL;
}

int mpmc_ring_enqueue(struct mpmc_ring *ring, uint32_t data) {
    uint32_t pos = atomic_load_explicit(&ring->head, memory_order_relaxed);
    struct ring_entry *entry;

    for (;;) {
        entry = &ring->entries[pos & ring->mask];
        uint32_t seq = atomic_load_explicit(&entry->seq, memory_order_acquire);
        int32_t diff = (int32_t)seq - (int32_t)pos;

        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(&ring->head, &pos, pos + 1,
                    memory_order_relaxed, memory_order_relaxed))
                break;
        } else if (diff < 0) {
            return -1; /* full */
        } else {
            pos = atomic_load_explicit(&ring->head, memory_order_relaxed);
        }
    }

    entry->data = data;
    atomic_store_explicit(&entry->seq, pos + 1, memory_order_release);
    return 0;
}

int mpmc_ring_dequeue(struct mpmc_ring *ring, uint32_t *data) {
    uint32_t pos = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    struct ring_entry *entry;

    for (;;) {
        entry = &ring->entries[pos & ring->mask];
        uint32_t seq = atomic_load_explicit(&entry->seq, memory_order_acquire);
        int32_t diff = (int32_t)seq - (int32_t)(pos + 1);

        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(&ring->tail, &pos, pos + 1,
                    memory_order_relaxed, memory_order_relaxed))
                break;
        } else if (diff < 0) {
            return -1; /* empty */
        } else {
            pos = atomic_load_explicit(&ring->tail, memory_order_relaxed);
        }
    }

    *data = entry->data;
    atomic_store_explicit(&entry->seq, pos + ring->capacity, memory_order_release);
    return 0;
}

int mpmc_ring_dequeue_batch(struct mpmc_ring *ring, uint32_t *out, int max) {
    int count = 0;
    while (count < max) {
        if (mpmc_ring_dequeue(ring, &out[count]) != 0)
            break;
        count++;
    }
    return count;
}

/* ================================================================
 * Packet Pool
 * ================================================================ */

int pkt_pool_init(struct pkt_pool *pool, uint32_t capacity) {
    pool->capacity = capacity;

    pool->slots = calloc(capacity, sizeof(struct pkt_slot));
    if (!pool->slots) {
        fprintf(stderr, "[POOL] Failed to allocate %u slots (%zu MB)\n",
                capacity, (size_t)capacity * sizeof(struct pkt_slot) / (1024 * 1024));
        return -1;
    }

    if (mpmc_ring_init(&pool->free_ring, capacity) != 0) {
        free(pool->slots);
        return -1;
    }

    /* Push all slot indices onto free ring */
    for (uint32_t i = 0; i < capacity; i++)
        mpmc_ring_enqueue(&pool->free_ring, i);

    printf("[POOL] Allocated %u slots (%zu MB)\n",
           capacity, (size_t)capacity * sizeof(struct pkt_slot) / (1024 * 1024));
    return 0;
}

void pkt_pool_destroy(struct pkt_pool *pool) {
    mpmc_ring_destroy(&pool->free_ring);
    free(pool->slots);
    pool->slots = NULL;
}

int pkt_pool_alloc(struct pkt_pool *pool) {
    uint32_t idx;
    if (mpmc_ring_dequeue(&pool->free_ring, &idx) != 0)
        return -1;
    return (int)idx;
}

void pkt_pool_free(struct pkt_pool *pool, uint32_t idx) {
    mpmc_ring_enqueue(&pool->free_ring, idx);
}

/* ================================================================
 * Hash functions
 * ================================================================ */

static uint32_t jenkins_hash(const uint8_t *key, size_t len) {
    uint32_t hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash += key[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

uint32_t hash_5tuple(const uint8_t *pkt, uint32_t len) {
    if (len < 14 + 20) return 0;

    uint16_t ether_type = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (ether_type != 0x0800) return 0;

    const uint8_t *ip = pkt + 14;
    int ihl = (ip[0] & 0x0F) * 4;
    uint8_t proto = ip[9];

    uint8_t key[13];
    memcpy(key, ip + 12, 4);       /* src_ip */
    memcpy(key + 4, ip + 16, 4);   /* dst_ip */

    uint16_t src_port = 0, dst_port = 0;
    if ((uint32_t)(14 + ihl + 4) <= len && (proto == 6 || proto == 17)) {
        src_port = ((uint16_t)pkt[14 + ihl] << 8) | pkt[14 + ihl + 1];
        dst_port = ((uint16_t)pkt[14 + ihl + 2] << 8) | pkt[14 + ihl + 3];
    }

    memcpy(key + 8, &src_port, 2);
    memcpy(key + 10, &dst_port, 2);
    key[12] = proto;

    return jenkins_hash(key, 13);
}

uint32_t hash_ip_pair(const uint8_t *pkt, uint32_t len) {
    if (len < 14 + 20) return 0;
    /* Hash src_ip + dst_ip (8 bytes at IP offset 12) */
    return jenkins_hash(pkt + 14 + 12, 8);
}

/* ================================================================
 * Pipeline init/destroy
 * ================================================================ */

int pipeline_init(struct pipeline_ctx *ctx,
                  int num_outbound_workers,
                  int num_inbound_workers,
                  int wan_count, int local_count,
                  uint32_t ring_size, uint32_t pool_size) {
    memset(ctx, 0, sizeof(*ctx));

    if (ring_size == 0) ring_size = RING_DEFAULT_SIZE;
    if (pool_size == 0) pool_size = POOL_DEFAULT_SIZE;

    /* Packet pool */
    if (pkt_pool_init(&ctx->pool, pool_size) != 0)
        return -1;

    /* Outbound worker rings */
    ctx->num_outbound_workers = num_outbound_workers;
    ctx->outbound_worker_rings = calloc(num_outbound_workers, sizeof(struct mpmc_ring));
    if (!ctx->outbound_worker_rings) goto fail_pool;
    for (int i = 0; i < num_outbound_workers; i++) {
        if (mpmc_ring_init(&ctx->outbound_worker_rings[i], ring_size) != 0)
            goto fail_outbound;
    }

    /* Inbound worker rings */
    ctx->num_inbound_workers = num_inbound_workers;
    ctx->inbound_worker_rings = calloc(num_inbound_workers, sizeof(struct mpmc_ring));
    if (!ctx->inbound_worker_rings) goto fail_outbound;
    for (int i = 0; i < num_inbound_workers; i++) {
        if (mpmc_ring_init(&ctx->inbound_worker_rings[i], ring_size) != 0)
            goto fail_inbound;
    }

    /* TX WAN rings */
    ctx->tx_wan_count = wan_count;
    ctx->tx_wan_rings = calloc(wan_count, sizeof(struct mpmc_ring));
    if (!ctx->tx_wan_rings) goto fail_inbound;
    for (int i = 0; i < wan_count; i++) {
        if (mpmc_ring_init(&ctx->tx_wan_rings[i], ring_size) != 0)
            goto fail_tx_wan;
    }

    /* TX LOCAL rings */
    ctx->tx_local_count = local_count;
    ctx->tx_local_rings = calloc(local_count, sizeof(struct mpmc_ring));
    if (!ctx->tx_local_rings) goto fail_tx_wan;
    for (int i = 0; i < local_count; i++) {
        if (mpmc_ring_init(&ctx->tx_local_rings[i], ring_size) != 0)
            goto fail_tx_local;
    }

    printf("[PIPELINE] outbound_workers=%d, inbound_workers=%d, "
           "ring_size=%u, pool_size=%u\n",
           num_outbound_workers, num_inbound_workers, ring_size, pool_size);

    return 0;

fail_tx_local:
    for (int i = 0; i < local_count; i++)
        mpmc_ring_destroy(&ctx->tx_local_rings[i]);
    free(ctx->tx_local_rings);
fail_tx_wan:
    for (int i = 0; i < wan_count; i++)
        mpmc_ring_destroy(&ctx->tx_wan_rings[i]);
    free(ctx->tx_wan_rings);
fail_inbound:
    for (int i = 0; i < num_inbound_workers; i++)
        mpmc_ring_destroy(&ctx->inbound_worker_rings[i]);
    free(ctx->inbound_worker_rings);
fail_outbound:
    for (int i = 0; i < num_outbound_workers; i++)
        mpmc_ring_destroy(&ctx->outbound_worker_rings[i]);
    free(ctx->outbound_worker_rings);
fail_pool:
    pkt_pool_destroy(&ctx->pool);
    return -1;
}

void pipeline_destroy(struct pipeline_ctx *ctx) {
    for (int i = 0; i < ctx->num_outbound_workers; i++)
        mpmc_ring_destroy(&ctx->outbound_worker_rings[i]);
    free(ctx->outbound_worker_rings);

    for (int i = 0; i < ctx->num_inbound_workers; i++)
        mpmc_ring_destroy(&ctx->inbound_worker_rings[i]);
    free(ctx->inbound_worker_rings);

    for (int i = 0; i < ctx->tx_wan_count; i++)
        mpmc_ring_destroy(&ctx->tx_wan_rings[i]);
    free(ctx->tx_wan_rings);

    for (int i = 0; i < ctx->tx_local_count; i++)
        mpmc_ring_destroy(&ctx->tx_local_rings[i]);
    free(ctx->tx_local_rings);

    pkt_pool_destroy(&ctx->pool);
}
