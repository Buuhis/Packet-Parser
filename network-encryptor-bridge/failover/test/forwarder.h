#ifndef FORWARDER_H
#define FORWARDER_H

#include "config.h"

struct forwarder {
    const struct app_config *cfg;
    int wan_count;
};

#endif // FORWARDER_H
