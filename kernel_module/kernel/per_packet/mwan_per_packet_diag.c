#include "mwan_per_packet_diag.h"

#include "../mwan_state.h"

#include <linux/atomic.h>
#include <linux/seq_file.h>

static atomic64_t selected[MAX_MWAN_TUNNELS];
static atomic64_t switches;
static atomic64_t reselections;
static atomic64_t evictions;
static atomic64_t completed;
static atomic64_t incomplete;

void mwan_pp_diag_reset(void)
{
    u32 i;

    for (i = 0; i < MAX_MWAN_TUNNELS; i++)
        atomic64_set(&selected[i], 0);
    atomic64_set(&switches, 0);
    atomic64_set(&reselections, 0);
    atomic64_set(&evictions, 0);
    atomic64_set(&completed, 0);
    atomic64_set(&incomplete, 0);
}

void mwan_pp_diag_selected(u16 tunnel_idx)
{
    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    if (tunnel_idx < MAX_MWAN_TUNNELS)
        atomic64_inc(&selected[tunnel_idx]);
}

void mwan_pp_diag_switched(void)
{
    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    atomic64_inc(&switches);
}

void mwan_pp_diag_reselected(void)
{
    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    atomic64_inc(&reselections);
}

void mwan_pp_diag_evicted(void)
{
    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    atomic64_inc(&evictions);
}

void mwan_pp_diag_complete(bool whole_packet_sent)
{
    if (!READ_ONCE(mwan_l2_diag_enabled))
        return;
    if (whole_packet_sent)
        atomic64_inc(&completed);
    else
        atomic64_inc(&incomplete);
}

void mwan_pp_diag_show(struct seq_file *m)
{
    u32 i;

    seq_printf(m,
               "per_packet switches=%lld reselections=%lld evictions=%lld completed=%lld incomplete=%lld\n",
               atomic64_read(&switches),
               atomic64_read(&reselections),
               atomic64_read(&evictions),
               atomic64_read(&completed),
               atomic64_read(&incomplete));
    seq_puts(m, "per_packet_selected");
    for (i = 0; i < MAX_MWAN_TUNNELS; i++) {
        s64 count = atomic64_read(&selected[i]);

        if (count)
            seq_printf(m, " tunnel%u=%lld", i, count);
    }
    seq_putc(m, '\n');
}
