// SPDX-License-Identifier: GPL-2.0
#include "mwan_replay.h"

#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define MWAN_REPLAY_WINDOW_MASK (MWAN_REPLAY_WINDOW_BITS - 1U)

struct mwan_replay_key_window {
    DECLARE_BITMAP(seen, MWAN_REPLAY_WINDOW_BITS);
    u64 highest_nonce;
    u8 key_id;
    bool valid;
    bool initialized;
};

struct mwan_l2_replay_manager {
    refcount_t refs;
    spinlock_t lock;
    struct mwan_replay_key_window keys[MWAN_REPLAY_MAX_KEYS];
    struct mwan_replay_stats stats;
};

static struct mwan_replay_key_window *
mwan_l2_replay_find_key(struct mwan_l2_replay_manager *manager, u8 key_id)
{
    unsigned int i;

    for (i = 0; i < MWAN_REPLAY_MAX_KEYS; i++) {
	if (manager->keys[i].valid && manager->keys[i].key_id == key_id)
	    return &manager->keys[i];
    }
    return NULL;
}

static bool mwan_l2_replay_key_retained(u8 key_id, u8 current_key_id,
					bool prev_key_valid, u8 prev_key_id,
					bool next_key_valid, u8 next_key_id)
{
    return key_id == current_key_id ||
	   (prev_key_valid && key_id == prev_key_id) ||
	   (next_key_valid && key_id == next_key_id);
}

struct mwan_l2_replay_manager *
mwan_l2_replay_manager_alloc(u8 current_key_id, bool prev_key_valid,
			     u8 prev_key_id)
{
    struct mwan_l2_replay_manager *manager;
    int ret;

    if (!current_key_id || (prev_key_valid && !prev_key_id))
	return NULL;
    manager = kvzalloc(sizeof(*manager), GFP_KERNEL);
    if (!manager)
	return NULL;
    refcount_set(&manager->refs, 1);
    spin_lock_init(&manager->lock);

    ret = mwan_l2_replay_prepare_key(manager, current_key_id);
    if (!ret && prev_key_valid)
	ret = mwan_l2_replay_prepare_key(manager, prev_key_id);
    if (ret) {
	kvfree_sensitive(manager, sizeof(*manager));
	return NULL;
    }
    return manager;
}

struct mwan_l2_replay_manager *
mwan_l2_replay_manager_get(struct mwan_l2_replay_manager *manager)
{
    if (manager)
	refcount_inc(&manager->refs);
    return manager;
}

void mwan_l2_replay_manager_put(struct mwan_l2_replay_manager *manager)
{
    if (manager && refcount_dec_and_test(&manager->refs))
	kvfree_sensitive(manager, sizeof(*manager));
}

int mwan_l2_replay_prepare_key(struct mwan_l2_replay_manager *manager,
			       u8 key_id)
{
    struct mwan_replay_key_window *slot = NULL;
    unsigned int i;

    if (!manager || !key_id)
	return -EINVAL;
    spin_lock_bh(&manager->lock);
    slot = mwan_l2_replay_find_key(manager, key_id);
    if (slot)
	goto out;
    for (i = 0; i < MWAN_REPLAY_MAX_KEYS; i++) {
	if (!manager->keys[i].valid) {
	    slot = &manager->keys[i];
	    break;
	}
    }
    if (!slot) {
	spin_unlock_bh(&manager->lock);
	return -ENOSPC;
    }
    bitmap_zero(slot->seen, MWAN_REPLAY_WINDOW_BITS);
    slot->highest_nonce = 0;
    slot->key_id = key_id;
    slot->initialized = false;
    slot->valid = true;
out:
    spin_unlock_bh(&manager->lock);
    return 0;
}

void mwan_l2_replay_forget_key(struct mwan_l2_replay_manager *manager,
			       u8 key_id)
{
    struct mwan_replay_key_window *slot;

    if (!manager || !key_id)
	return;
    spin_lock_bh(&manager->lock);
    slot = mwan_l2_replay_find_key(manager, key_id);
    if (slot)
	memset(slot, 0, sizeof(*slot));
    spin_unlock_bh(&manager->lock);
}

void mwan_l2_replay_retain_keys(struct mwan_l2_replay_manager *manager,
				u8 current_key_id, bool prev_key_valid,
				u8 prev_key_id, bool next_key_valid,
				u8 next_key_id)
{
    unsigned int i;

    if (!manager)
	return;
    spin_lock_bh(&manager->lock);
    for (i = 0; i < MWAN_REPLAY_MAX_KEYS; i++) {
	struct mwan_replay_key_window *slot = &manager->keys[i];

	if (!slot->valid ||
	    mwan_l2_replay_key_retained(slot->key_id, current_key_id,
					prev_key_valid, prev_key_id,
					next_key_valid, next_key_id))
	    continue;
	memset(slot, 0, sizeof(*slot));
    }
    spin_unlock_bh(&manager->lock);
}

static void mwan_l2_replay_advance(struct mwan_replay_key_window *slot,
				   u64 packet_nonce)
{
    u64 advance = packet_nonce - slot->highest_nonce;
    u32 start;
    u32 count;
    u32 first;

    if (advance >= MWAN_REPLAY_WINDOW_BITS) {
	bitmap_zero(slot->seen, MWAN_REPLAY_WINDOW_BITS);
    } else {
	start = (u32)((slot->highest_nonce + 1) &
		      MWAN_REPLAY_WINDOW_MASK);
	count = (u32)advance;
	first = min_t(u32, count, MWAN_REPLAY_WINDOW_BITS - start);
	bitmap_clear(slot->seen, start, first);
	if (count > first)
	    bitmap_clear(slot->seen, 0, count - first);
    }
    slot->highest_nonce = packet_nonce;
}

int mwan_l2_replay_check_and_mark(struct mwan_l2_replay_manager *manager,
				  u8 key_id, u64 packet_nonce)
{
    struct mwan_replay_key_window *slot;
    u64 distance;
    unsigned long bit;
    int ret = 0;

    if (!manager || !key_id || !packet_nonce)
	return -EINVAL;
    spin_lock_bh(&manager->lock);
    slot = mwan_l2_replay_find_key(manager, key_id);
    if (!slot) {
	manager->stats.no_key++;
	ret = -ENOKEY;
	goto out;
    }
    if (!slot->initialized) {
	slot->highest_nonce = packet_nonce;
	slot->initialized = true;
	__set_bit((unsigned long)(packet_nonce & MWAN_REPLAY_WINDOW_MASK),
		  slot->seen);
	manager->stats.accepted++;
	goto out;
    }
    if (packet_nonce > slot->highest_nonce) {
	mwan_l2_replay_advance(slot, packet_nonce);
	__set_bit((unsigned long)(packet_nonce & MWAN_REPLAY_WINDOW_MASK),
		  slot->seen);
	manager->stats.accepted++;
	goto out;
    }

    distance = slot->highest_nonce - packet_nonce;
    if (distance >= MWAN_REPLAY_WINDOW_BITS) {
	manager->stats.too_old++;
	ret = -ERANGE;
	goto out;
    }
    bit = (unsigned long)(packet_nonce & MWAN_REPLAY_WINDOW_MASK);
    if (test_bit(bit, slot->seen)) {
	manager->stats.duplicate++;
	ret = -EALREADY;
	goto out;
    }
    __set_bit(bit, slot->seen);
    manager->stats.accepted++;
    manager->stats.accepted_reordered++;
out:
    spin_unlock_bh(&manager->lock);
    return ret;
}

void mwan_l2_replay_get_stats(struct mwan_l2_replay_manager *manager,
			      struct mwan_replay_stats *stats)
{
    if (!stats)
	return;
    memset(stats, 0, sizeof(*stats));
    if (!manager)
	return;
    spin_lock_bh(&manager->lock);
    *stats = manager->stats;
    spin_unlock_bh(&manager->lock);
}

void mwan_l2_replay_reset_stats(struct mwan_l2_replay_manager *manager)
{
    if (!manager)
	return;
    spin_lock_bh(&manager->lock);
    memset(&manager->stats, 0, sizeof(manager->stats));
    spin_unlock_bh(&manager->lock);
}
