#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <stdint.h>

/* ================================================================ */
/* ==================== PROTOCOL CONSTANTS ======================== */
/* ================================================================ */

#define MWAN_ETHERTYPE 0x88B5                               /* IEEE 802 Local Experimental */

/* ---- VXLAN Encapsulation (RFC 7348) ---- */
#define VXLAN_PORT          4789                            /* Standard VXLAN UDP port */
#define VXLAN_HDR_SIZE      8                               /* VXLAN header is 8 bytes */
#define VXLAN_DEFAULT_VNI   100                             /* Default Virtual Network Identifier */
#define VXLAN_FLAGS         0x08                            /* I-flag set (VNI is valid) */

/* VXLAN Header: 8 bytes
 * [Flags (1)] [Reserved (3)] [VNI (3)] [Reserved (1)]
 */
typedef struct __attribute__((packed)) {
    uint8_t  flags;
    uint8_t  reserved1[3];
    uint8_t  vni[3];        /* 24-bit VNI in network byte order */
    uint8_t  reserved2;
} vxlan_hdr_t;

/* Build a VXLAN header in-place */
static inline void vxlan_hdr_build(vxlan_hdr_t *hdr, uint32_t vni) {
    hdr->flags = VXLAN_FLAGS;
    hdr->reserved1[0] = 0;
    hdr->reserved1[1] = 0;
    hdr->reserved1[2] = 0;
    hdr->vni[0] = (uint8_t)((vni >> 16) & 0xFF);
    hdr->vni[1] = (uint8_t)((vni >> 8)  & 0xFF);
    hdr->vni[2] = (uint8_t)(vni & 0xFF);
    hdr->reserved2 = 0;
}

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

#endif /* MWAN_PROTO_H */
