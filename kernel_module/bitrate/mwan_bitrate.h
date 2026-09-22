#ifndef MWAN_BITRATE_H
#define MWAN_BITRATE_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * Per-owner-worker CPU-time token bucket.
 *
 * Tokens are nanoseconds of actual L2-PQC TX processing time, not line-rate
 * bytes.  This makes the limiter protect the resource that has been observed
 * to saturate: the CPU running crypto and transmit completion.
 */
struct mwan_bitrate_state {
    spinlock_t lock;
    u64 last_refill_ns;
    s64 tokens_ns;
    atomic64_t throttle_events;
    atomic64_t wait_ns;
    atomic64_t max_wait_ns;
    atomic64_t accounted_ns;
    atomic64_t packets;
    atomic64_t bytes;
    atomic64_t control_bypass;
    atomic64_t max_debt_ns;
};

struct mwan_bitrate_snapshot {
    bool enabled;
    u32 target_bp;
    u64 burst_ns;
    s64 tokens_ns;
    u64 throttle_events;
    u64 wait_ns;
    u64 max_wait_ns;
    u64 accounted_ns;
    u64 packets;
    u64 bytes;
    u64 control_bypass;
    u64 max_debt_ns;
};

void mwan_bitrate_init(struct mwan_bitrate_state *state);
void mwan_bitrate_reset_stats(struct mwan_bitrate_state *state);
void mwan_bitrate_wait(struct mwan_bitrate_state *state, bool control);
void mwan_bitrate_account(struct mwan_bitrate_state *state,
                          u64 processing_ns, u32 bytes);
void mwan_bitrate_snapshot(struct mwan_bitrate_state *state,
                           struct mwan_bitrate_snapshot *snapshot);

#endif /* MWAN_BITRATE_H */
