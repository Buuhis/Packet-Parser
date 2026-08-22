#include "failover.h"

/*
 * The standalone BFD manager deliberately owns the stabilizer in bfd.c so a
 * raw BFD transition can never bypass it.  This translation unit is kept as
 * the future integration boundary: after standalone approval, the daemon
 * callback that publishes tunnel state will be implemented here.
 */
