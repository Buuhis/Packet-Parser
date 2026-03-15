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

/* ---- VXLAN Fragment Metadata (stored in reserved1 bytes) ---- */
#define VXLAN_FRAG_NONE     0   /* Unfragmented packet */
#define VXLAN_FRAG_FIRST    1   /* First fragment (contains Eth+IP headers + first half payload) */
#define VXLAN_FRAG_LAST     2   /* Last fragment (second half payload only) */

/* VXLAN Header: 8 bytes
 * [Flags (1)] [pkt_id_hi (1)] [pkt_id_lo (1)] [frag_index (1)] [VNI (3)] [Reserved (1)]
 *
 * reserved1[0] = pkt_id high byte
 * reserved1[1] = pkt_id low byte
 * reserved1[2] = frag_index (0=none, 1=first, 2=last)
 */
typedef struct __attribute__((packed)) {
    uint8_t  flags;
    uint8_t  reserved1[3];
    uint8_t  vni[3];        /* 24-bit VNI in network byte order */
    uint8_t  reserved2;
} vxlan_hdr_t;

/* Build a standard VXLAN header (no fragmentation) */
static inline void vxlan_hdr_build(vxlan_hdr_t *hdr, uint32_t vni) {
    hdr->flags = VXLAN_FLAGS;
    hdr->reserved1[0] = 0;
    hdr->reserved1[1] = 0;
    hdr->reserved1[2] = VXLAN_FRAG_NONE;
    hdr->vni[0] = (uint8_t)((vni >> 16) & 0xFF);
    hdr->vni[1] = (uint8_t)((vni >> 8)  & 0xFF);
    hdr->vni[2] = (uint8_t)(vni & 0xFF);
    hdr->reserved2 = 0;
}

/* Build a VXLAN header with fragment metadata */
static inline void vxlan_hdr_build_frag(vxlan_hdr_t *hdr, uint32_t vni,
                                         uint16_t pkt_id, uint8_t frag_index) {
    hdr->flags = VXLAN_FLAGS;
    hdr->reserved1[0] = (uint8_t)(pkt_id >> 8);
    hdr->reserved1[1] = (uint8_t)(pkt_id & 0xFF);
    hdr->reserved1[2] = frag_index;
    hdr->vni[0] = (uint8_t)((vni >> 16) & 0xFF);
    hdr->vni[1] = (uint8_t)((vni >> 8)  & 0xFF);
    hdr->vni[2] = (uint8_t)(vni & 0xFF);
    hdr->reserved2 = 0;
}

/* Read fragment metadata from VXLAN header */
static inline void vxlan_hdr_read_frag(const vxlan_hdr_t *hdr,
                                        uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)hdr->reserved1[0] << 8) | hdr->reserved1[1];
    *frag_index = hdr->reserved1[2];
}

#define MWAN_NE_TUNNEL_MTU 1418                             /* ne_tunnel L3 MTU */

#endif /* MWAN_PROTO_H */
