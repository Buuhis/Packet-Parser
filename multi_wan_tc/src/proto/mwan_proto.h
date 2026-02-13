#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <stdint.h>

/* ================================================================ */
/* ==================== PROTOCOL CONSTANTS ======================== */
/* ================================================================ */

#define MWAN_ETHERTYPE 0x88B5                               /* IEEE 802 Local Experimental */

/* 
 * NOTE: The following constants were part of the previous fragmentation logic
 * and are kept here for historical reference or future use if needed, 
 * although they are currently unused in the Simple Forwarding mode.
 */
#define MWAN_NE_TUNNEL_MTU 1418                             /* ne_tunnel L3 MTU */
#define MWAN_HDR_SIZE 8                                     /* sizeof(mwan_hdr_t) - DEPRECATED */
#define MWAN_MAX_CHUNK (MWAN_NE_TUNNEL_MTU - MWAN_HDR_SIZE) /* 1410 - DEPRECATED */
#define MWAN_FRAG_THRESHOLD 1400                            /* IP packets <= this: no fragment - DEPRECATED */
#define MWAN_MAX_FRAGS 48                                   /* ceil(1500/1410) = 2 max - DEPRECATED */

/* Utility function used in other places? mwan_now_ns is used in logger/utils sometimes? No, used in reorder.c mainly. */
/* Let's keep mwan_now_ns declaration if it's defined in utils somewhere, but wait, it was defined in a deleted file? */
/* Ah, mwan_now_ns was implemented in reorder.c or a separate file? */
/* Let's check where mwan_now_ns was implemented. If it was in reorder.c, then it is gone. */
/* I used mwan_now_ns in afpkt.c logging? No i removed it. */
/* I used mwan_now_ns in main.c? No. */

#endif /* MWAN_PROTO_H */
