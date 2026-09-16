#ifndef MWAN_LB_MODE_H
#define MWAN_LB_MODE_H

#include <linux/types.h>

bool mwan_lb_per_packet_enabled(void);
const char *mwan_lb_mode_name(void);

#endif /* MWAN_LB_MODE_H */
