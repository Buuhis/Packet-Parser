#include "mwan_per_packet.h"

#include "mwan_lb_mode.h"
#include "mwan_per_packet_diag.h"
#include "../mwan_multicore.h"
#include "../mwan_state.h"

#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#define MWAN_PACKET_BUCKETS       4096U
#define MWAN_PACKET_WAYS             4U
#define MWAN_PACKET_IDLE_TIMEOUT (60UL * HZ)

struct mwan_packet_entry {
    struct mwan_l2_flow_key key;
    u32 generation;
    u32 packets;
    u32 window;
    unsigned long last_seen;
    u16 selected_tunnel;
    bool valid;
};

struct mwan_packet_bucket {
    spinlock_t lock;
    struct mwan_packet_entry ways[MWAN_PACKET_WAYS];
};

static struct mwan_packet_bucket *mwan_packet_table;

/* A value of one is genuine packet-by-packet rotation.  The parameters stay
 * tunable for controlled comparison tests without changing the mode define. */
static unsigned int mwan_packet_tcp_window = 1U;
static unsigned int mwan_packet_udp_window = 1U;
static unsigned int mwan_packet_other_window = 1U;

module_param_named(per_packet_tcp_window, mwan_packet_tcp_window, uint, 0644);
MODULE_PARM_DESC(per_packet_tcp_window,
                 "Original TCP packets sent on one tunnel before rotation");
module_param_named(per_packet_udp_window, mwan_packet_udp_window, uint, 0644);
MODULE_PARM_DESC(per_packet_udp_window,
                 "Original UDP datagrams sent on one tunnel before rotation");
module_param_named(per_packet_other_window, mwan_packet_other_window, uint,
                   0644);
MODULE_PARM_DESC(per_packet_other_window,
                 "Other IPv4 packets sent on one tunnel before rotation");

static void mwan_packet_normalize_key(struct mwan_l2_flow_key *key)
{
    if (!key)
        return;
    if ((__force u32)key->saddr > (__force u32)key->daddr ||
        (key->saddr == key->daddr &&
         (__force u16)key->sport > (__force u16)key->dport)) {
        __be32 addr = key->saddr;
        __be16 port = key->sport;

        key->saddr = key->daddr;
        key->daddr = addr;
        key->sport = key->dport;
        key->dport = port;
    }
}

static u32 mwan_packet_key_hash(const struct mwan_l2_flow_key *key)
{
    u32 ports = ((__force u32)key->sport << 16) |
                (__force u32)key->dport;

    if (!key->saddr && !key->daddr && !ports)
        return key->fallback_hash;
    return jhash_3words((__force u32)key->saddr,
                        (__force u32)key->daddr,
                        ports ^ ((u32)key->protocol << 24),
                        0x7061636bU);
}

static bool mwan_packet_key_equal(const struct mwan_l2_flow_key *left,
                                  const struct mwan_l2_flow_key *right)
{
    bool tuple_present = left->saddr || left->daddr ||
                         left->sport || left->dport;

    return left->saddr == right->saddr &&
           left->daddr == right->daddr &&
           left->sport == right->sport &&
           left->dport == right->dport &&
           left->protocol == right->protocol &&
           (tuple_present || left->fallback_hash == right->fallback_hash);
}

static u32 mwan_packet_window(const struct mwan_l2_flow_key *key)
{
    u32 window;

    if (key->protocol == IPPROTO_TCP)
        window = READ_ONCE(mwan_packet_tcp_window);
    else if (key->protocol == IPPROTO_UDP)
        window = READ_ONCE(mwan_packet_udp_window);
    else
        window = READ_ONCE(mwan_packet_other_window);
    return max_t(u32, window, 1U);
}

static bool mwan_packet_tunnel_eligible(const struct mwan_config *cfg,
                                        u16 tunnel_idx,
                                        u16 routed_tunnel_idx)
{
    const struct mwan_tunnel *tun;
    const struct mwan_tunnel *routed;

    if (!cfg || tunnel_idx >= cfg->num_tunnels ||
        routed_tunnel_idx >= cfg->num_tunnels)
        return false;
    tun = &cfg->tunnels[tunnel_idx];
    routed = &cfg->tunnels[routed_tunnel_idx];
    return READ_ONCE(tun->published_up) && READ_ONCE(tun->weight) != 0 &&
           READ_ONCE(tun->dev) && tun->encap_type == routed->encap_type;
}

static int mwan_packet_pick_nth(const struct mwan_config *cfg,
                                u16 routed_tunnel_idx, u32 ordinal,
                                u16 *selected)
{
    u32 eligible = 0;
    u32 i;

    for (i = 0; i < cfg->num_tunnels; i++) {
        if (mwan_packet_tunnel_eligible(cfg, (u16)i, routed_tunnel_idx))
            eligible++;
    }
    if (!eligible)
        return -ENETDOWN;
    ordinal %= eligible;
    for (i = 0; i < cfg->num_tunnels; i++) {
        if (!mwan_packet_tunnel_eligible(cfg, (u16)i,
                                         routed_tunnel_idx))
            continue;
        if (!ordinal--) {
            *selected = (u16)i;
            return 0;
        }
    }
    return -ENETDOWN;
}

static int mwan_packet_pick_after(const struct mwan_config *cfg,
                                  u16 routed_tunnel_idx,
                                  u16 current_tunnel,
                                  u16 *selected)
{
    u32 step;

    for (step = 1; step <= cfg->num_tunnels; step++) {
        u16 candidate = (u16)((current_tunnel + step) % cfg->num_tunnels);

        if (mwan_packet_tunnel_eligible(cfg, candidate,
                                        routed_tunnel_idx)) {
            *selected = candidate;
            return 0;
        }
    }
    return -ENETDOWN;
}

bool mwan_per_packet_enabled(void)
{
    return mwan_lb_per_packet_enabled() &&
           READ_ONCE(mwan_packet_table) != NULL;
}

static void mwan_packet_advance(struct mwan_config *cfg,
                                struct mwan_packet_entry *entry,
                                u16 routed_tunnel_idx)
{
    u16 next;

    entry->packets++;
    if (entry->packets < entry->window)
        return;
    entry->packets = 0;
    if (!mwan_packet_pick_after(cfg, routed_tunnel_idx,
                                entry->selected_tunnel, &next) &&
        next != entry->selected_tunnel) {
        entry->selected_tunnel = next;
        mwan_pp_diag_switched();
    }
}

int mwan_per_packet_select(struct mwan_config *cfg,
                           const struct mwan_tx_flow_info *info,
                           u16 routed_tunnel_idx,
                           u16 *selected_tunnel_idx,
                           struct mwan_per_packet_ticket *ticket)
{
    struct mwan_packet_bucket *bucket;
    struct mwan_packet_entry *entry = NULL;
    struct mwan_packet_entry *victim;
    struct mwan_l2_flow_key key;
    unsigned long oldest;
    u32 hash;
    u32 way;
    int err = 0;

    if (!cfg || !info || !selected_tunnel_idx || !mwan_per_packet_enabled())
        return -EINVAL;
    if (routed_tunnel_idx >= cfg->num_tunnels)
        return -EINVAL;

    key = info->key;
    mwan_packet_normalize_key(&key);
    hash = mwan_packet_key_hash(&key);
    bucket = &mwan_packet_table[hash & (MWAN_PACKET_BUCKETS - 1U)];
    if (ticket)
        memset(ticket, 0, sizeof(*ticket));

    spin_lock_bh(&bucket->lock);
    victim = &bucket->ways[0];
    oldest = victim->last_seen;
    for (way = 0; way < MWAN_PACKET_WAYS; way++) {
        struct mwan_packet_entry *candidate = &bucket->ways[way];

        if (candidate->valid && candidate->generation == cfg->generation &&
            mwan_packet_key_equal(&candidate->key, &key)) {
            entry = candidate;
            break;
        }
        if (!candidate->valid ||
            time_after(jiffies, candidate->last_seen +
                                 MWAN_PACKET_IDLE_TIMEOUT)) {
            victim = candidate;
            oldest = 0;
        } else if (oldest && time_before(candidate->last_seen, oldest)) {
            victim = candidate;
            oldest = candidate->last_seen;
        }
    }

    if (!entry) {
        entry = victim;
        if (entry->valid)
            mwan_pp_diag_evicted();
        memset(entry, 0, sizeof(*entry));
        entry->key = key;
        entry->generation = cfg->generation;
        entry->window = mwan_packet_window(&key);
        err = mwan_packet_pick_nth(cfg, routed_tunnel_idx, hash,
                                   &entry->selected_tunnel);
        if (err)
            goto out;
        entry->valid = true;
    } else if (!mwan_packet_tunnel_eligible(
                   cfg, entry->selected_tunnel, routed_tunnel_idx)) {
        err = mwan_packet_pick_nth(cfg, routed_tunnel_idx, hash,
                                   &entry->selected_tunnel);
        if (err)
            goto out;
        entry->packets = 0;
        mwan_pp_diag_reselected();
    }

    entry->window = mwan_packet_window(&key);
    entry->last_seen = jiffies;
    *selected_tunnel_idx = entry->selected_tunnel;
    mwan_pp_diag_selected(entry->selected_tunnel);
    if (ticket) {
        ticket->selected_tunnel = entry->selected_tunnel;
        ticket->protocol = key.protocol;
        ticket->valid = true;
    }

    /* Reserve the cursor while holding the bucket lock.  This is deliberate:
     * advancing only from an asynchronous completion lets multiple CPUs
     * choose the same tunnel before any completion updates the entry. */
    mwan_packet_advance(cfg, entry, routed_tunnel_idx);
out:
    spin_unlock_bh(&bucket->lock);
    return err;
}

void mwan_per_packet_complete(const struct mwan_per_packet_ticket *ticket,
                              bool whole_packet_sent)
{
    if (!ticket || !ticket->valid || !mwan_lb_per_packet_enabled())
        return;
    mwan_pp_diag_complete(whole_packet_sent);
}

int mwan_per_packet_init(void)
{
    u32 i;

    mwan_pp_diag_reset();
    if (!mwan_lb_per_packet_enabled()) {
        pr_info("mwan_kmod: load-balance mode=%s\n", mwan_lb_mode_name());
        return 0;
    }
    mwan_packet_table = kvcalloc(MWAN_PACKET_BUCKETS,
                                 sizeof(*mwan_packet_table), GFP_KERNEL);
    if (!mwan_packet_table)
        return -ENOMEM;
    for (i = 0; i < MWAN_PACKET_BUCKETS; i++)
        spin_lock_init(&mwan_packet_table[i].lock);
    pr_info("mwan_kmod: load-balance mode=%s tcp_window=%u udp_window=%u other_window=%u\n",
            mwan_lb_mode_name(), READ_ONCE(mwan_packet_tcp_window),
            READ_ONCE(mwan_packet_udp_window),
            READ_ONCE(mwan_packet_other_window));
    return 0;
}

void mwan_per_packet_cleanup(void)
{
    struct mwan_packet_bucket *table = mwan_packet_table;

    WRITE_ONCE(mwan_packet_table, NULL);
    synchronize_rcu();
    kvfree(table);
}

void mwan_per_packet_diag_reset(void)
{
    mwan_pp_diag_reset();
}

void mwan_per_packet_diag_show(struct seq_file *m)
{
    seq_printf(m, "load_balance mode=%s tcp_window=%u udp_window=%u other_window=%u table=%u\n",
               mwan_lb_mode_name(), READ_ONCE(mwan_packet_tcp_window),
               READ_ONCE(mwan_packet_udp_window),
               READ_ONCE(mwan_packet_other_window),
               READ_ONCE(mwan_packet_table) != NULL);
    mwan_pp_diag_show(m);
}
