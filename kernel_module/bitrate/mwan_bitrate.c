#include "mwan_bitrate.h"

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/math64.h>

/*
 * Compile-time controls only.  Change these values, rebuild mwan_kmod.ko and
 * reload it.  There are deliberately no module parameters.
 *
 * TARGET_BP is the share of wall time an owner worker may spend in L2-PQC TX
 * (10000 == 100%).  It is a CPU headroom guard, not a Mbps limit.
 */
#define MWAN_BITRATE_ENABLE          1
#define MWAN_BITRATE_TARGET_BP    7000U
#define MWAN_BITRATE_BP_MAX      10000U
#define MWAN_BITRATE_BURST_NS    (10ULL * NSEC_PER_MSEC)
#define MWAN_BITRATE_MAX_SLEEP_NS (5ULL * NSEC_PER_MSEC)
#define MWAN_BITRATE_MIN_SLEEP_US  50U

#if MWAN_BITRATE_TARGET_BP == 0 || \
    MWAN_BITRATE_TARGET_BP > MWAN_BITRATE_BP_MAX
#error "MWAN_BITRATE_TARGET_BP must be in the range 1..10000"
#endif

#if MWAN_BITRATE_ENABLE
static void mwan_bitrate_atomic64_max(atomic64_t *maximum, u64 value)
{
    s64 old = atomic64_read(maximum);

    while (value > (u64)old) {
        s64 observed = atomic64_cmpxchg(maximum, old, (s64)value);

        if (observed == old)
            break;
        old = observed;
    }
}

static void mwan_bitrate_refill_locked(struct mwan_bitrate_state *state,
                                       u64 now_ns)
{
    u64 elapsed_ns;
    u64 refill_ns;

    if (unlikely(now_ns <= state->last_refill_ns))
        return;

    elapsed_ns = now_ns - state->last_refill_ns;
    state->last_refill_ns = now_ns;
    refill_ns = mul_u64_u32_div(elapsed_ns, MWAN_BITRATE_TARGET_BP,
                                MWAN_BITRATE_BP_MAX);
    state->tokens_ns = min_t(s64, state->tokens_ns + (s64)refill_ns,
                             (s64)MWAN_BITRATE_BURST_NS);
}
#endif

void mwan_bitrate_init(struct mwan_bitrate_state *state)
{
    if (!state)
        return;

    spin_lock_init(&state->lock);
    state->last_refill_ns = ktime_get_ns();
    state->tokens_ns = MWAN_BITRATE_BURST_NS;
    mwan_bitrate_reset_stats(state);
}

void mwan_bitrate_reset_stats(struct mwan_bitrate_state *state)
{
    if (!state)
        return;

    atomic64_set(&state->throttle_events, 0);
    atomic64_set(&state->wait_ns, 0);
    atomic64_set(&state->max_wait_ns, 0);
    atomic64_set(&state->accounted_ns, 0);
    atomic64_set(&state->packets, 0);
    atomic64_set(&state->bytes, 0);
    atomic64_set(&state->control_bypass, 0);
    atomic64_set(&state->max_debt_ns, 0);
}

void mwan_bitrate_wait(struct mwan_bitrate_state *state, bool control)
{
#if MWAN_BITRATE_ENABLE
    u64 wait_started_ns = 0;

    if (unlikely(!state))
        return;
    if (unlikely(control)) {
        atomic64_inc(&state->control_bypass);
        return;
    }

    for (;;) {
        u64 now_ns = ktime_get_ns();
        u64 deficit_ns;
        u64 sleep_ns;
        unsigned long flags;
        unsigned long sleep_us;

        spin_lock_irqsave(&state->lock, flags);
        mwan_bitrate_refill_locked(state, now_ns);
        if (state->tokens_ns >= 0) {
            spin_unlock_irqrestore(&state->lock, flags);
            break;
        }
        deficit_ns = (u64)-state->tokens_ns;
        sleep_ns = DIV_ROUND_UP_ULL(deficit_ns * MWAN_BITRATE_BP_MAX,
                                    MWAN_BITRATE_TARGET_BP);
        sleep_ns = min_t(u64, sleep_ns, MWAN_BITRATE_MAX_SLEEP_NS);
        spin_unlock_irqrestore(&state->lock, flags);

        if (!wait_started_ns) {
            wait_started_ns = now_ns;
            atomic64_inc(&state->throttle_events);
        }
        sleep_us = max_t(unsigned long,
                         (unsigned long)DIV_ROUND_UP_ULL(sleep_ns,
                                                       NSEC_PER_USEC),
                         MWAN_BITRATE_MIN_SLEEP_US);
        usleep_range(sleep_us, sleep_us + max_t(unsigned long, 10,
                                                sleep_us >> 3));
    }

    if (wait_started_ns) {
        u64 waited_ns = ktime_get_ns() - wait_started_ns;

        atomic64_add(waited_ns, &state->wait_ns);
        mwan_bitrate_atomic64_max(&state->max_wait_ns, waited_ns);
    }
#else
    (void)state;
    (void)control;
#endif
}

void mwan_bitrate_account(struct mwan_bitrate_state *state,
                          u64 processing_ns, u32 bytes)
{
#if MWAN_BITRATE_ENABLE
    unsigned long flags;
    u64 debt_ns = 0;

    if (unlikely(!state))
        return;

    spin_lock_irqsave(&state->lock, flags);
    mwan_bitrate_refill_locked(state, ktime_get_ns());
    state->tokens_ns -= (s64)processing_ns;
    if (state->tokens_ns < 0)
        debt_ns = (u64)-state->tokens_ns;
    spin_unlock_irqrestore(&state->lock, flags);

    atomic64_add(processing_ns, &state->accounted_ns);
    atomic64_inc(&state->packets);
    atomic64_add(bytes, &state->bytes);
    mwan_bitrate_atomic64_max(&state->max_debt_ns, debt_ns);
#else
    (void)state;
    (void)processing_ns;
    (void)bytes;
#endif
}

void mwan_bitrate_snapshot(struct mwan_bitrate_state *state,
                           struct mwan_bitrate_snapshot *snapshot)
{
    unsigned long flags;

    if (!snapshot)
        return;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->enabled = MWAN_BITRATE_ENABLE;
    snapshot->target_bp = MWAN_BITRATE_TARGET_BP;
    snapshot->burst_ns = MWAN_BITRATE_BURST_NS;
    if (!state)
        return;

    spin_lock_irqsave(&state->lock, flags);
#if MWAN_BITRATE_ENABLE
    mwan_bitrate_refill_locked(state, ktime_get_ns());
#endif
    snapshot->tokens_ns = state->tokens_ns;
    spin_unlock_irqrestore(&state->lock, flags);
    snapshot->throttle_events = atomic64_read(&state->throttle_events);
    snapshot->wait_ns = atomic64_read(&state->wait_ns);
    snapshot->max_wait_ns = atomic64_read(&state->max_wait_ns);
    snapshot->accounted_ns = atomic64_read(&state->accounted_ns);
    snapshot->packets = atomic64_read(&state->packets);
    snapshot->bytes = atomic64_read(&state->bytes);
    snapshot->control_bypass = atomic64_read(&state->control_bypass);
    snapshot->max_debt_ns = atomic64_read(&state->max_debt_ns);
}
