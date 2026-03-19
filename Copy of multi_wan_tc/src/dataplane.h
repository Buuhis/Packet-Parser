#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "app_context.h"

int  dataplane_start(app_context_t *ctx);
void dataplane_stop(void);
int  dataplane_is_active(void);

#endif /* DATAPLANE_H */
