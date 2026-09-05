#include "mwan_tunnel_balance.h"
#include "mwan_state.h"

#include <linux/atomic.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/rcupdate.h>

/* Load is refreshed only when a new flow needs a path. Existing packets keep
 * their O(1) sticky-flow lookup and never scan the tunnel array. */
#define MWAN_BALANCE_SAMPLE_NS       (250ULL * NSEC_PER_MSEC)
#define MWAN_BALANCE_STALE_NS       (2000ULL * NSEC_PER_MSEC)
#define MWAN_BALANCE_FLOW_SCALE     1000000ULL

static void mwan_tunnel_balance_refresh_locked(struct mwan_config *cfg,
                                               u64 now_ns)
{
    u64 elapsed_ns;
    unsigned long now = jiffies;
    u32 i;

    if (!cfg->tunnel_balance_sample_ns) {
        cfg->tunnel_balance_sample_ns = now_ns;
        for (i = 0; i < cfg->num_tunnels; i++)
            cfg->tunnels[i].balance_sample_bytes =
                (u64)atomic64_read(&cfg->tunnels[i].balance_tx_bytes);
        return;
    }

    elapsed_ns = now_ns - cfg->tunnel_balance_sample_ns;
    /* An idle data path must not retain a non-zero rate merely because BFD
     * continues to use it. Control traffic is excluded from byte accounting,
     * and this clears the last data EWMA without waiting for the flow-table
     * object to expire. Keep same-window admissions: they represent new data
     * flows whose packets may not have reached the worker yet. */
    for (i = 0; i < cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &cfg->tunnels[i];
        unsigned long last_data = READ_ONCE(tun->balance_last_data);

        if (last_data &&
            time_after(now, last_data + MWAN_FLOW_BALANCE_IDLE_TIMEOUT))
            tun->balance_ewma_bps = 0;
    }

    if (elapsed_ns < MWAN_BALANCE_SAMPLE_NS)
        return;

    for (i = 0; i < cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &cfg->tunnels[i];
        u64 current_bytes = (u64)atomic64_read(&tun->balance_tx_bytes);
        u64 delta_bytes = current_bytes - tun->balance_sample_bytes;
        unsigned long last_data = READ_ONCE(tun->balance_last_data);
        bool data_idle = last_data &&
            time_after(now, last_data + MWAN_FLOW_BALANCE_IDLE_TIMEOUT);
        u64 current_bps;

        if (data_idle) {
            tun->balance_ewma_bps = 0;
            tun->balance_sample_bytes = current_bytes;
            atomic_set(&tun->balance_admitted_flows, 0);
            continue;
        }

        /* Use milliseconds so a long idle interval cannot overflow the
         * delta_bytes multiplier. The refresh interval is at least 250 ms,
         * therefore the divisor can never be zero here. */
        current_bps = div64_u64(
            delta_bytes * 1000ULL,
            div64_u64(elapsed_ns, NSEC_PER_MSEC));
        if (!tun->balance_ewma_bps || elapsed_ns >= MWAN_BALANCE_STALE_NS)
            tun->balance_ewma_bps = current_bps;
        else
            tun->balance_ewma_bps =
                div64_u64(tun->balance_ewma_bps * 3 + current_bps, 4);
        tun->balance_sample_bytes = current_bytes;
        atomic_set(&tun->balance_admitted_flows, 0);
    }
    cfg->tunnel_balance_sample_ns = now_ns;
}

bool mwan_tunnel_balance_is_active(const struct mwan_config *cfg,
                                   u16 tunnel_idx)
{
    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return false;
    return READ_ONCE(cfg->tunnels[tunnel_idx].published_up) &&
           READ_ONCE(cfg->tunnels[tunnel_idx].weight) != 0;
}

/* Select the lowest effective load/weight, where effective load includes an
 * immediate reservation for flows admitted in the current sample. If loads
 * are equal, select the lowest active-flow count/weight. Userspace sends
 * weight=1 for every tunnel when profile weighting is disabled. The weighted
 * active LUT is only a stable final tie-breaker; an existing flow never uses
 * it to migrate while its pinned tunnel remains UP.
 */
static int mwan_tunnel_balance_select_locked(struct mwan_config *cfg,
                                             u32 flow_hash)
{
    const struct mwan_active_paths *active;
    u64 best_load = U64_MAX;
    u64 best_flows = U64_MAX;
    u64 reservation_unit = 1;
    u64 total_load = 0;
    u64 total_flows = 0;
    u32 best_rank = U32_MAX;
    int preferred = -1;
    int best = -1;
    u32 i;

    rcu_read_lock();
    active = rcu_dereference(cfg->active_paths);
    if (active && active->active_count && active->total_weight) {
        u8 idx = active->tunnel_idx_lut[
            flow_hash & (MWAN_LUT_SIZE - 1)];

        if (idx < cfg->num_tunnels)
            preferred = idx;
    }
    rcu_read_unlock();

    /* Estimate one newly admitted flow from the data already observed. This
     * reservation is not a bandwidth promise; it only prevents a burst of
     * new flows from all consuming one frozen 250-ms load snapshot. At cold
     * start the unit remains one, so immediate reservations still spread the
     * burst according to active weights. */
    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];

        if (!mwan_tunnel_balance_is_active(cfg, (u16)i))
            continue;
        total_load += tun->balance_ewma_bps;
        total_flows += (u64)atomic_read(&tun->balance_active_flows);
    }
    if (total_load && total_flows)
        reservation_unit = max_t(u64,
            div64_u64(total_load, total_flows), 1);

    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];
        u32 weight = READ_ONCE(tun->weight);
        u64 admitted =
            (u64)atomic_read(&tun->balance_admitted_flows);
        u64 effective_load;
        u64 load_score;
        u64 flow_score;
        u32 rank;

        if (!mwan_tunnel_balance_is_active(cfg, (u16)i))
            continue;
        effective_load = tun->balance_ewma_bps;
        if (admitted &&
            admitted <= div64_u64(U64_MAX - effective_load,
                                  reservation_unit))
            effective_load += admitted * reservation_unit;
        else if (admitted)
            effective_load = U64_MAX;
        load_score = div64_u64(effective_load, weight);
        flow_score = div64_u64(
            (u64)atomic_read(&tun->balance_active_flows) *
                MWAN_BALANCE_FLOW_SCALE,
            weight);
        rank = (int)i == preferred ? 0 :
            (jhash_2words(flow_hash, i, 0x6d77616eU) | 1U);

        if (best < 0 || load_score < best_load ||
            (load_score == best_load && flow_score < best_flows) ||
            (load_score == best_load && flow_score == best_flows &&
             rank < best_rank)) {
            best = (int)i;
            best_load = load_score;
            best_flows = flow_score;
            best_rank = rank;
        }
    }
    return best;
}

void mwan_tunnel_balance_init(struct mwan_config *cfg)
{
    u32 i;

    if (!cfg)
        return;
    spin_lock_init(&cfg->tunnel_balance_lock);
    cfg->tunnel_balance_sample_ns = 0;
    for (i = 0; i < cfg->num_tunnels; i++) {
        atomic64_set(&cfg->tunnels[i].balance_tx_bytes, 0);
        atomic_set(&cfg->tunnels[i].balance_active_flows, 0);
        atomic_set(&cfg->tunnels[i].balance_admitted_flows, 0);
        cfg->tunnels[i].balance_sample_bytes = 0;
        cfg->tunnels[i].balance_ewma_bps = 0;
        cfg->tunnels[i].balance_last_data = 0;
    }
}

int mwan_tunnel_balance_assign_flow(struct mwan_config *cfg, u32 flow_hash)
{
    int selected;

    if (!cfg)
        return -EINVAL;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    mwan_tunnel_balance_refresh_locked(cfg, ktime_get_ns());
    selected = mwan_tunnel_balance_select_locked(cfg, flow_hash);
    if (selected >= 0) {
        atomic_inc(&cfg->tunnels[selected].balance_active_flows);
        atomic_inc(&cfg->tunnels[selected].balance_admitted_flows);
    }
    spin_unlock_bh(&cfg->tunnel_balance_lock);
    return selected >= 0 ? selected : -ENETDOWN;
}

void mwan_tunnel_balance_activate_flow(struct mwan_config *cfg,
                                       u16 tunnel_idx)
{
    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    atomic_inc(&cfg->tunnels[tunnel_idx].balance_active_flows);
    atomic_inc(&cfg->tunnels[tunnel_idx].balance_admitted_flows);
    spin_unlock_bh(&cfg->tunnel_balance_lock);
}

int mwan_tunnel_balance_reassign_flow(struct mwan_config *cfg,
                                      u16 old_tunnel_idx, u32 flow_hash,
                                      bool old_counted)
{
    int selected;

    if (!cfg || old_tunnel_idx >= cfg->num_tunnels)
        return -EINVAL;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    mwan_tunnel_balance_refresh_locked(cfg, ktime_get_ns());
    selected = mwan_tunnel_balance_select_locked(cfg, flow_hash);
    if (selected >= 0) {
        if (selected != old_tunnel_idx) {
            atomic_inc(&cfg->tunnels[selected].balance_active_flows);
            atomic_inc(&cfg->tunnels[selected].balance_admitted_flows);
            if (old_counted)
                atomic_add_unless(
                    &cfg->tunnels[old_tunnel_idx].balance_active_flows,
                    -1, 0);
        } else if (!old_counted) {
            atomic_inc(&cfg->tunnels[selected].balance_active_flows);
            atomic_inc(&cfg->tunnels[selected].balance_admitted_flows);
        }
    }
    spin_unlock_bh(&cfg->tunnel_balance_lock);
    return selected >= 0 ? selected : -ENETDOWN;
}

void mwan_tunnel_balance_release_flow(struct mwan_config *cfg,
                                      u16 tunnel_idx)
{
    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    atomic_add_unless(&cfg->tunnels[tunnel_idx].balance_active_flows,
                      -1, 0);
    spin_unlock_bh(&cfg->tunnel_balance_lock);
}

void mwan_tunnel_balance_account_bytes(struct mwan_config *cfg,
                                       u16 tunnel_idx, u32 bytes)
{
    if (!cfg || tunnel_idx >= cfg->num_tunnels || !bytes)
        return;
    atomic64_add(bytes, &cfg->tunnels[tunnel_idx].balance_tx_bytes);
    WRITE_ONCE(cfg->tunnels[tunnel_idx].balance_last_data, jiffies);
}
