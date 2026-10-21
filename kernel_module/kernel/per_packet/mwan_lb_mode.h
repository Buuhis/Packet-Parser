#ifndef MWAN_LB_MODE_H
#define MWAN_LB_MODE_H

#include <linux/types.h>
#include "../mwan_proto.h"

u8 mwan_lb_mode_get(void);
int mwan_lb_mode_set(u8 mode);
bool mwan_lb_per_packet_enabled(void);
const char *mwan_lb_mode_name(void);
const char *mwan_lb_mode_value_name(u8 mode);

#endif /* MWAN_LB_MODE_H */
