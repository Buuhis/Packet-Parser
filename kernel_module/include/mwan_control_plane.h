#ifndef MWAN_CONTROL_PLANE_H
#define MWAN_CONTROL_PLANE_H

/*
 * Userspace/kernel ABI for locally generated PQC handshake packets.
 *
 * The mark is metadata local to the Linux networking stack; it is not put on
 * the wire.  Only the PQC handshake TX socket sets this bit.  Data applications
 * using UDP/7090 therefore remain ordinary L2-PQC payload.
 */
#define MWAN_PQC_HS_SOCKET_MARK      0x40000000U
#define MWAN_PQC_HS_SOCKET_MARK_MASK 0x40000000U

#endif /* MWAN_CONTROL_PLANE_H */
