#ifndef MWAN_MULTICORE_H
#define MWAN_MULTICORE_H

#include <linux/skbuff.h>

#include "mwan_state.h"

enum mwan_flow_hash_source {
    MWAN_HASH_INVALID = 0,
    MWAN_HASH_CACHED,
    MWAN_HASH_DISSECTOR,
    MWAN_HASH_FALLBACK,
};

struct mwan_tx_flow_info {
    struct mwan_l2_flow_key key;
    u32 flow_id;
    u32 hash_before;
    enum mwan_flow_hash_source hash_source;
    bool tuple_valid;
    bool hash_was_cached;
    bool hash_is_l4;
    bool hash_is_sw;
};

const char *mwan_multicore_hash_source_name(enum mwan_flow_hash_source source);
u32 mwan_multicore_flow_info(struct sk_buff *skb,
                             struct mwan_tx_flow_info *info);
bool mwan_multicore_packet_is_control(struct sk_buff *skb);
bool mwan_multicore_rx_congestion_feedback(struct mwan_l2_worker *worker,
                                           struct sk_buff *skb);

/* On success ownership of skb and the caller's flow reference moves to the
 * selected worker.  On failure skb remains owned by the caller. */
int mwan_multicore_tx_submit(struct sk_buff *skb, struct mwan_config *cfg,
                             u16 tunnel_idx,
                             const struct mwan_tx_flow_info *info,
                             bool closing, u32 *flow_seq, int *owner_cpu);

#endif /* MWAN_MULTICORE_H */
