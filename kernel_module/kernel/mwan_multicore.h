#ifndef MWAN_MULTICORE_H
#define MWAN_MULTICORE_H

#include <linux/skbuff.h>

#include "mwan_state.h"

enum mwan_flow_hash_source {
    MWAN_HASH_INVALID = 0,
    MWAN_HASH_CACHED,
    MWAN_HASH_DISSECTOR,
    MWAN_HASH_FALLBACK,
    MWAN_HASH_IPSEC_SA,
};

struct mwan_tx_flow_info {
    struct mwan_l2_flow_key key;
    u32 flow_id;
    u32 hash_before;
    __be32 ipsec_sequence;
    enum mwan_flow_hash_source hash_source;
    bool tuple_valid;
    bool ipsec_sa_valid;
    bool ipsec_control;
    bool hash_was_cached;
    bool hash_is_l4;
    bool hash_is_sw;
};

enum mwan_packet_class {
    MWAN_PACKET_CONTROL = 0,
    MWAN_PACKET_TCP_DATA,
    MWAN_PACKET_UDP_DATA,
    MWAN_PACKET_OTHER_DATA,
};

/* One lookup in POST_ROUTING owns this reference while encap performs any
 * GSO segmentation or IP fragmentation. Each queued skb takes a short-lived
 * additional reference from it; the dispatcher releases the original after
 * the synchronous encap wrapper returns. */
struct mwan_tx_flow_context {
    struct mwan_tx_flow_info info;
    struct mwan_l2_tx_flow *flow;
    enum mwan_packet_class packet_class;
};

const char *mwan_multicore_hash_source_name(enum mwan_flow_hash_source source);
u32 mwan_multicore_flow_info(struct sk_buff *skb,
                             struct mwan_tx_flow_info *info);
enum mwan_packet_class mwan_multicore_packet_classify(struct sk_buff *skb);
bool mwan_multicore_rx_congestion_feedback(struct mwan_l2_worker *worker,
                                           struct sk_buff *skb);

/* This function always consumes preselected_flow when it is non-NULL. On
 * success ownership of skb and that flow reference moves to the selected
 * worker. On failure skb remains owned by the caller. */
int mwan_multicore_tx_submit(struct sk_buff *skb, struct mwan_config *cfg,
                             u16 tunnel_idx,
                             const struct mwan_tx_flow_info *info,
                             struct mwan_l2_tx_flow *preselected_flow,
                             enum mwan_packet_class packet_class,
                             bool closing, u32 *flow_seq, int *owner_cpu);

void mwan_pipeline_rx_maybe_promote(struct mwan_config *cfg,
                                    struct mwan_l2_rx_flow *flow,
                                    struct mwan_l2_worker *worker,
                                    u32 flow_id);
int mwan_pipeline_rx_submit(struct sk_buff *skb,
                            struct mwan_l2_worker *crypto_worker,
                            struct mwan_l2_rx_flow *flow, u32 flow_seq);
void mwan_pipeline_wait_for_room(struct mwan_config *cfg, int pipeline_idx,
                                 bool tx, u32 bytes, bool priority);

#endif /* MWAN_MULTICORE_H */
