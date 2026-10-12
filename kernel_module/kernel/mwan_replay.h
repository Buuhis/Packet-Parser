/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MWAN_REPLAY_H
#define MWAN_REPLAY_H

#include <linux/types.h>

/* packet_nonce is global to one L2-PQC sender session.  Keep a window large
 * enough for packets encrypted on different CPUs and paths to complete out
 * of order without weakening duplicate detection after an RX flow expires. */
#define MWAN_REPLAY_WINDOW_BITS 65536U
#define MWAN_REPLAY_MAX_KEYS    3U

struct mwan_l2_replay_manager;

struct mwan_replay_stats {
    u64 accepted;
    u64 accepted_reordered;
    u64 duplicate;
    u64 too_old;
    u64 no_key;
};

struct mwan_l2_replay_manager *
mwan_l2_replay_manager_alloc(u8 current_key_id, bool prev_key_valid,
			     u8 prev_key_id);
struct mwan_l2_replay_manager *
mwan_l2_replay_manager_get(struct mwan_l2_replay_manager *manager);
void mwan_l2_replay_manager_put(struct mwan_l2_replay_manager *manager);

int mwan_l2_replay_prepare_key(struct mwan_l2_replay_manager *manager,
			       u8 key_id);
void mwan_l2_replay_forget_key(struct mwan_l2_replay_manager *manager,
			       u8 key_id);
void mwan_l2_replay_retain_keys(struct mwan_l2_replay_manager *manager,
				u8 current_key_id, bool prev_key_valid,
				u8 prev_key_id, bool next_key_valid,
				u8 next_key_id);

/* Must be called only after AEAD authentication succeeds.  Updating the
 * window from unauthenticated header data would let a forged high nonce move
 * the window and suppress legitimate traffic. */
int mwan_l2_replay_check_and_mark(struct mwan_l2_replay_manager *manager,
				  u8 key_id, u64 packet_nonce);

void mwan_l2_replay_get_stats(struct mwan_l2_replay_manager *manager,
			      struct mwan_replay_stats *stats);
void mwan_l2_replay_reset_stats(struct mwan_l2_replay_manager *manager);

#endif /* MWAN_REPLAY_H */
