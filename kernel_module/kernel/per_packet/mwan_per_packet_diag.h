#ifndef MWAN_PER_PACKET_DIAG_H
#define MWAN_PER_PACKET_DIAG_H

#include <linux/types.h>

struct seq_file;

void mwan_pp_diag_reset(void);
void mwan_pp_diag_selected(u16 tunnel_idx);
void mwan_pp_diag_switched(void);
void mwan_pp_diag_reselected(void);
void mwan_pp_diag_evicted(void);
void mwan_pp_diag_complete(bool whole_packet_sent);
void mwan_pp_diag_show(struct seq_file *m);

#endif /* MWAN_PER_PACKET_DIAG_H */
