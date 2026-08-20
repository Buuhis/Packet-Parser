#ifndef SDWAN_FAILOVER_H
#define SDWAN_FAILOVER_H

/*
 * The standalone phase deliberately exposes only BFD manager APIs from bfd.h.
 * This header reserves the integration boundary: a later main daemon will
 * consume published UP/DOWN callbacks here, not raw BFD transitions.
 */
#include "bfd.h"

#endif /* SDWAN_FAILOVER_H */
