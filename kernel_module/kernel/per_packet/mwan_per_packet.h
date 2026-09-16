#ifndef MWAN_PER_PACKET_H
#define MWAN_PER_PACKET_H

#include <linux/types.h>

struct mwan_config;
struct mwan_tx_flow_info;
struct seq_file;

struct mwan_per_packet_ticket {
    u16 selected_tunnel;
    u8 protocol;
    bool valid;
};

int mwan_per_packet_init(void);
void mwan_per_packet_cleanup(void);
bool mwan_per_packet_enabled(void);

/* Select one tunnel before GSO segmentation or IPv4 fragmentation.  Every
 * child skb of the original packet must inherit this selected tunnel. */
int mwan_per_packet_select(struct mwan_config *cfg,
                           const struct mwan_tx_flow_info *info,
                           u16 routed_tunnel_idx,
                           u16 *selected_tunnel_idx,
                           struct mwan_per_packet_ticket *ticket);
void mwan_per_packet_complete(const struct mwan_per_packet_ticket *ticket,
                              bool whole_packet_sent);

void mwan_per_packet_diag_reset(void);
void mwan_per_packet_diag_show(struct seq_file *m);

#endif /* MWAN_PER_PACKET_H */
