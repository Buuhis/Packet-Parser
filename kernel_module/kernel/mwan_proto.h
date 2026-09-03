#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <linux/types.h>

#define MWAN_GENL_NAME "MWAN_STEER"
#define MWAN_GENL_VERSION 4

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
    MWAN_CMD_GET_TUNNEL_PEERS, /* query runtime peer learned by discovery */
    MWAN_CMD_SET_TUNNEL_STATE, /* publish one BFD-stabilized data-path state */
    MWAN_CMD_GET_TUNNEL_STATE, /* query the state currently enforced by kernel */
    MWAN_CMD_STAGE_PQC_KEY,    /* install NEXT without changing TX CURRENT */
    MWAN_CMD_ACTIVATE_PQC_KEY, /* atomically make NEXT the TX CURRENT key */
    MWAN_CMD_RETIRE_PQC_KEY,   /* stop accepting and erase PREV */
    MWAN_CMD_GET_PQC_KEY_STATE,/* query key generations, never key material */
    MWAN_CMD_ABORT_PQC_KEY,    /* discard an uncommitted NEXT key */
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
    MWAN_ATTR_QUERY_IFINDEX, /* u32: data tunnel requested by userspace */
    MWAN_ATTR_PEER_TUNNEL_IP,/* NLA_BINARY: network-order IPv4 address */
    MWAN_ATTR_PEER_RESOLVED, /* u8: peer tunnel IP discovery completed */
    MWAN_ATTR_CONFIG_GENERATION, /* u32: full-config generation */
    MWAN_ATTR_TUNNEL_STATE,      /* u8: 0=DOWN, 1=UP */
    MWAN_ATTR_STATE_SEQUENCE,    /* u32: monotonic within one generation */
    MWAN_ATTR_REKEY_EPOCH,       /* u64: idempotent userspace transaction */
    MWAN_ATTR_NEXT_KEY,          /* NLA_BINARY: staged 32-byte PQC key */
    MWAN_ATTR_NEXT_KEY_ID,       /* u8: staged traffic-key generation */
    MWAN_ATTR_KEY_STATE,         /* u8: enum mwan_pqc_key_state */
    __MWAN_ATTR_MAX,
};
#define MWAN_ATTR_MAX (__MWAN_ATTR_MAX - 1)

enum mwan_pqc_key_state {
    MWAN_PQC_KEY_STABLE = 0,
    MWAN_PQC_KEY_STAGED,
    MWAN_PQC_KEY_ACTIVE_WITH_PREV,
};

/* ---- Tunnel Sub-Attributes ---- */
enum mwan_tun_attrs {
    MWAN_TUN_UNSPEC = 0,
    MWAN_TUN_IFINDEX,     /* u32 */
    MWAN_TUN_WEIGHT,      /* u32 */
    __MWAN_TUN_MAX,
};
#define MWAN_TUN_MAX (__MWAN_TUN_MAX - 1)

#endif /* MWAN_PROTO_H */
