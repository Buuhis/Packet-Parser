#include "mwan_tunnel_balance.h"
#include "mwan_state.h"

#include <linux/atomic.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/rcupdate.h>

/* Load is refreshed only when a new flow needs a path. Steady-state flows
 * keep their O(1) sticky lookup; only a flow explicitly marked as admitted
 * during degraded capacity performs one bounded scan after paths recover. */
#define MWAN_BALANCE_SAMPLE_NS       (250ULL * NSEC_PER_MSEC)
#define MWAN_BALANCE_STALE_NS       (2000ULL * NSEC_PER_MSEC)
#define MWAN_BALANCE_FLOW_SCALE     1000000ULL

static u64
mwan_tunnel_balance_read_bytes(const struct mwan_config *cfg, u16 tunnel_idx,
                               unsigned long *last_data)
{
    u64 total = 0;
    unsigned long latest = 0;
    int i;

    if (!cfg || tunnel_idx >= cfg->num_tunnels)
        return 0;
    for (i = 0; i < cfg->num_workers; i++) {
        const struct mwan_l2_worker *worker = &cfg->l2_workers[i];
        u64 value;
        unsigned long worker_last;

        if (!worker->balance_tx_bytes || !worker->balance_last_data)
            continue;
        value = (u64)atomic64_read(
            &worker->balance_tx_bytes[tunnel_idx]);
        if (U64_MAX - total < value)
            total = U64_MAX;
        else
            total += value;
        worker_last = READ_ONCE(worker->balance_last_data[tunnel_idx]);
        if (time_after(worker_last, latest))
            latest = worker_last;
    }
    if (last_data)
        *last_data = latest;
    return total;
}

static void mwan_tunnel_balance_refresh_locked(struct mwan_config *cfg,
                                               u64 now_ns)
{
    u64 elapsed_ns;
    unsigned long now = jiffies;
    u32 i;

    if (!cfg->tunnel_balance_sample_ns) {
        cfg->tunnel_balance_sample_ns = now_ns;
        for (i = 0; i < cfg->num_tunnels; i++) {
            unsigned long last_data = 0;

            cfg->tunnels[i].balance_sample_bytes =
                mwan_tunnel_balance_read_bytes(cfg, (u16)i, &last_data);
            cfg->tunnels[i].balance_last_data = last_data;
        }
        return;
    }

    elapsed_ns = now_ns - cfg->tunnel_balance_sample_ns;
    /* An idle data path must not retain a non-zero rate merely because BFD
     * continues to use it. Control traffic is excluded from byte accounting,
     * and this clears the last data EWMA without waiting for the flow-table
     * object to expire. Keep same-window admissions: they represent new data
     * flows whose packets may not have reached the worker yet. */
    if (elapsed_ns < MWAN_BALANCE_SAMPLE_NS) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            struct mwan_tunnel *tun = &cfg->tunnels[i];
            unsigned long last_data = 0;

            (void)mwan_tunnel_balance_read_bytes(cfg, (u16)i,
                                                 &last_data);
            tun->balance_last_data = last_data;
            if (last_data && time_after(
                    now, last_data + MWAN_FLOW_BALANCE_IDLE_TIMEOUT))
                tun->balance_ewma_bps = 0;
        }
        return;
    }

    for (i = 0; i < cfg->num_tunnels; i++) {
        struct mwan_tunnel *tun = &cfg->tunnels[i];
        unsigned long last_data = 0;
        u64 current_bytes = mwan_tunnel_balance_read_bytes(
            cfg, (u16)i, &last_data);
        u64 delta_bytes = current_bytes - tun->balance_sample_bytes;
        bool data_idle = last_data &&
            time_after(now, last_data + MWAN_FLOW_BALANCE_IDLE_TIMEOUT);
        u64 current_bps;

        tun->balance_last_data = last_data;

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
                                             u32 flow_hash,
                                             u16 *active_count)
{
    const struct mwan_active_paths *active;
    u64 best_load = U64_MAX;
    u64 best_flows = U64_MAX;
    u64 reservation_unit = 1;
    u64 total_load = 0;
    u64 total_flows = 0;
    u32 best_rank = U32_MAX;
    u16 published_active_count = 0;
    u16 eligible_active_count = 0;
    u16 selectable_active_count = 0;
    int preferred = -1;
    int best = -1;
    u32 i;

    rcu_read_lock();
    active = rcu_dereference(cfg->active_paths);
    if (active && active->active_count && active->total_weight) {
        u8 idx = active->tunnel_idx_lut[
            flow_hash & (MWAN_LUT_SIZE - 1)];

        published_active_count = (u16)active->active_count;
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
        eligible_active_count++;
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
        selectable_active_count++;
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
    if (active_count)
        *active_count = min(published_active_count,
                            min(eligible_active_count,
                                selectable_active_count));
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
        atomic_set(&cfg->tunnels[i].balance_active_flows, 0);
        atomic_set(&cfg->tunnels[i].balance_admitted_flows, 0);
        cfg->tunnels[i].balance_sample_bytes = 0;
        cfg->tunnels[i].balance_ewma_bps = 0;
        cfg->tunnels[i].balance_last_data = 0;
    }
}

int mwan_tunnel_balance_assign_flow(struct mwan_config *cfg, u32 flow_hash,
                                    u16 *active_count)
{
    int selected;

    if (!cfg)
        return -EINVAL;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    mwan_tunnel_balance_refresh_locked(cfg, ktime_get_ns());
    selected = mwan_tunnel_balance_select_locked(cfg, flow_hash,
                                                  active_count);
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
    selected = mwan_tunnel_balance_select_locked(cfg, flow_hash, NULL);
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

int mwan_tunnel_balance_move_flow(struct mwan_config *cfg,
                                  u16 old_tunnel_idx, u16 new_tunnel_idx,
                                  bool old_counted)
{
    int ret = 0;

    if (!cfg || old_tunnel_idx >= cfg->num_tunnels ||
        new_tunnel_idx >= cfg->num_tunnels)
        return -EINVAL;

    spin_lock_bh(&cfg->tunnel_balance_lock);
    if (!mwan_tunnel_balance_is_active(cfg, new_tunnel_idx)) {
        ret = -ENETDOWN;
        goto out_unlock;
    }

    if (new_tunnel_idx != old_tunnel_idx) {
        atomic_inc(&cfg->tunnels[new_tunnel_idx].balance_active_flows);
        atomic_inc(&cfg->tunnels[new_tunnel_idx].balance_admitted_flows);
        if (old_counted)
            atomic_add_unless(
                &cfg->tunnels[old_tunnel_idx].balance_active_flows,
                -1, 0);
    } else if (!old_counted) {
        atomic_inc(&cfg->tunnels[new_tunnel_idx].balance_active_flows);
        atomic_inc(&cfg->tunnels[new_tunnel_idx].balance_admitted_flows);
    }

out_unlock:
    spin_unlock_bh(&cfg->tunnel_balance_lock);
    return ret;
}

/* Complete an admission that happened while the active path set was
 * degraded. Balance by active-flow count/weight, not the instantaneous byte
 * EWMA: immediately after recovery the old path has a non-zero sample and
 * the recovered path has none, so a load-only choice can move every flow and
 * merely invert the imbalance. Keep the old path on an equal score and move
 * a counted flow only when doing so improves the weighted distribution. */
int mwan_tunnel_balance_recover_flow(struct mwan_config *cfg,
                                     u16 old_tunnel_idx, u32 flow_hash,
                                     bool old_counted,
                                     u16 admission_active_count,
                                     u16 *active_count)
{
    const struct mwan_active_paths *active;
    u64 best_count = 0;
    u64 best_weight = 1;
    u32 best_rank = U32_MAX;
    u16 current_active_count = 0;
    int selected = -EAGAIN;
    u32 i;

    if (!cfg || old_tunnel_idx >= cfg->num_tunnels || !active_count)
        return -EINVAL;

    /* Avoid a tunnel-array scan on packets sent while the path set remains
     * degraded. The immutable RCU view makes this a constant-time check. */
    rcu_read_lock();
    active = rcu_dereference(cfg->active_paths);
    current_active_count = active ? (u16)active->active_count : 0;
    rcu_read_unlock();
    if (current_active_count <= admission_active_count)
        return -EAGAIN;

    current_active_count = 0;
    spin_lock_bh(&cfg->tunnel_balance_lock);
    for (i = 0; i < cfg->num_tunnels; i++) {
        const struct mwan_tunnel *tun = &cfg->tunnels[i];
        u64 count;
        u64 weight;
        u32 rank;

        if (!mwan_tunnel_balance_is_active(cfg, (u16)i))
            continue;
        current_active_count++;
        count = (u64)max_t(int,
                           atomic_read(&tun->balance_active_flows), 0);
        weight = READ_ONCE(tun->weight);
        rank = i == old_tunnel_idx ? 0 :
            (jhash_2words(flow_hash, i, 0x7265636fU) | 1U);
        if (selected < 0 || count * best_weight < best_count * weight ||
            (count * best_weight == best_count * weight &&
             rank < best_rank)) {
            selected = (int)i;
            best_count = count;
            best_weight = weight;
            best_rank = rank;
        }
    }
    if (selected < 0)
        goto out_unlock;
    if (current_active_count <= admission_active_count) {
        selected = -EAGAIN;
        goto out_unlock;
    }

    if (old_counted && selected != old_tunnel_idx) {
        const struct mwan_tunnel *old_tun =
            &cfg->tunnels[old_tunnel_idx];
        const struct mwan_tunnel *new_tun = &cfg->tunnels[selected];
        u64 old_count = (u64)max_t(
            int, atomic_read(&old_tun->balance_active_flows), 0);
        u64 new_count = (u64)max_t(
            int, atomic_read(&new_tun->balance_active_flows), 0);
        u64 old_weight = READ_ONCE(old_tun->weight);
        u64 new_weight = READ_ONCE(new_tun->weight);

        if (old_count * new_weight <=
            (new_count + 1) * old_weight)
            selected = old_tunnel_idx;
    }

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
    *active_count = current_active_count;
out_unlock:
    spin_unlock_bh(&cfg->tunnel_balance_lock);
    return selected;
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
                                       struct mwan_l2_worker *worker,
                                       u16 tunnel_idx, u32 bytes)
{
    if (!cfg || !worker || tunnel_idx >= cfg->num_tunnels || !bytes ||
        !worker->balance_tx_bytes || !worker->balance_last_data)
        return;
    atomic64_add(bytes, &worker->balance_tx_bytes[tunnel_idx]);
    WRITE_ONCE(worker->balance_last_data[tunnel_idx], jiffies);
}
