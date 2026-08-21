#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <linux/types.h>

#define MWAN_GENL_NAME "MWAN_STEER"
#define MWAN_GENL_VERSION 2

/* ---- Crypto Constants ---- */
#define MWAN_CRYPTO_MAGIC   0x4D57   /* ASCII "MW" — identify encrypted packets */
#define MWAN_CRYPTO_HDR_LEN 12       /* 2 (magic) + 1 (proto) + 1 (reserved) + 8 (seq) */
#define MWAN_GCM_TAG_LEN    16       /* AES-GCM Authentication Tag */
#define MWAN_GCM_IV_LEN     12       /* 4 (salt) + 8 (seq) */
#define MWAN_RFC4106_IV_LEN  8       /* RFC4106 explicit IV; 4-byte salt is part of the key */
#define MWAN_L2_HDR_LEN      20       /* 12-byte authenticated header + 8-byte explicit IV */
#define MWAN_MAX_KEY_LEN    32       /* AES-256 = 32 bytes */
#define MWAN_SALT_LEN        4
#define MWAN_FAKE_PROTOCOL  99       /* Fake L4 Protocol to hide real protocol (TCP/UDP) */
#define MWAN_L2_PQC_ETHERTYPE 0x88B5 /* Custom EtherType for L2-PQC packets */

/* ---- Crypto Type Enum ---- */
enum mwan_crypt_type {
    MWAN_CRYPT_AES_GCM_128 = 0,
    MWAN_CRYPT_AES_GCM_256 = 1,
    MWAN_CRYPT_PQC_GCM = 2,
};

/* ---- MWAN Crypto Header (prepended to encrypted payload) ---- */
struct mwan_crypto_hdr {
    __be16 magic;      /* 0x4D57 ("MW") */
    __u8 proto;        /* Original IP L4 protocol */
    __u8 key_id;       /* PQC traffic-key generation (0 = legacy current) */
    __be64 seq;        /* Sequence number (dynamic part of IV) */
} __attribute__((packed));

/* RFC4106 accepts 20 bytes here: the first 12 are authenticated fields and
 * the final 8 carry the explicit IV that is combined with the key salt.
 *
 * flow_token layout:
 *   bits 63..56: key generation ID
 *   bits 55..0 : random connection cookie
 *
 * A connection cookie, rather than a truncated hash-table bucket, keeps the
 * reorder state of unrelated short-lived TCP/UDP flows independent. */
struct mwan_l2_pqc_hdr {
    __be64 flow_token;    /* 8-bit key ID + 56-bit connection cookie */
    __be32 flow_seq;      /* 32-bit sequence local to this connection */
    __be64 packet_nonce;  /* 8-byte globally unique RFC4106 explicit IV */
} __attribute__((packed));

/* ---- Generic Netlink Commands ---- */
enum mwan_genl_cmds {
    MWAN_CMD_UNSPEC = 0,
    MWAN_CMD_SET_CONFIG,  /* sdwan send to mwan_kmod */
    MWAN_CMD_GET_TUNNEL_PEERS,
    MWAN_CMD_SET_TUNNEL_STATE,
    __MWAN_CMD_MAX,
};
#define MWAN_CMD_MAX (__MWAN_CMD_MAX - 1)

/* ---- Generic Netlink Attributes ---- */
enum mwan_genl_attrs {
    MWAN_ATTR_UNSPEC = 0,
    MWAN_ATTR_NODE_ID,    /* u32 */
    MWAN_ATTR_TUNNELS,    /* Nested array of tunnels */
    MWAN_ATTR_ENCRYPT_ON,    /* u8: 0=off, 1=on */
    MWAN_ATTR_ENCRYPT_TYPE,  /* u8: enum mwan_crypt_type */
    MWAN_ATTR_ENCRYPT_KEY,   /* NLA_BINARY: raw key bytes (16 or 32) */
    MWAN_ATTR_ENCRYPT_SALT,  /* NLA_BINARY: 4 bytes salt */
    MWAN_ATTR_ENCRYPT_LAYER, /* u8: 2=L2 (MACsec), 3=L3 (Overlay) */
    MWAN_ATTR_KEY_ID,        /* u8: current PQC traffic-key generation */
    MWAN_ATTR_PREV_KEY,      /* NLA_BINARY: previous 32-byte PQC key */
    MWAN_ATTR_PREV_KEY_ID,   /* u8: previous PQC traffic-key generation */
    MWAN_ATTR_TUNNEL_IFINDEX, /* u32: target of a state update */
    MWAN_ATTR_TUNNEL_UP,      /* u8: published BFD state */
    MWAN_ATTR_STATE_SEQUENCE, /* u32: reject stale state updates */
    __MWAN_ATTR_MAX,
};
#define MWAN_ATTR_MAX (__MWAN_ATTR_MAX - 1)

/* ---- Tunnel Sub-Attributes ---- */
enum mwan_tun_attrs {
    MWAN_TUN_UNSPEC = 0,
    MWAN_TUN_IFINDEX,     /* u32 */
    MWAN_TUN_WEIGHT,      /* u32 */
    MWAN_TUN_PEER_IPV4,   /* u32: network byte order */
    MWAN_TUN_PEER_MAC,    /* binary: ETH_ALEN bytes */
    MWAN_TUN_PEER_GENERATION, /* u32 */
    MWAN_TUN_UP,          /* u8: current published state */
    MWAN_TUN_STATE_SEQUENCE, /* u32 */
    MWAN_TUN_CONFIG_IFINDEX, /* u32: ifindex received from userspace */
    MWAN_TUN_LOCAL_IPV4,     /* u32: network byte order */
    MWAN_TUN_IFNAME,         /* NUL-terminated interface name */
    __MWAN_TUN_MAX,
};
#define MWAN_TUN_MAX (__MWAN_TUN_MAX - 1)

#endif /* MWAN_PROTO_H */
