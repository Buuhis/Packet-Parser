#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#include <linux/types.h>

#define MWAN_GENL_NAME "MWAN_STEER"
#define MWAN_GENL_VERSION 1

/* ---- Crypto Constants ---- */
#define MWAN_CRYPTO_MAGIC   0x4D57   /* ASCII "MW" — identify encrypted packets */
#define MWAN_CRYPTO_HDR_LEN 12       /* 2 (magic) + 1 (proto) + 1 (reserved) + 8 (seq) */
#define MWAN_GCM_TAG_LEN    16       /* AES-GCM Authentication Tag */
#define MWAN_GCM_IV_LEN     12       /* 4 (salt) + 8 (seq) */
#define MWAN_MAX_KEY_LEN    32       /* AES-256 = 32 bytes */
#define MWAN_SALT_LEN        4
#define MWAN_FAKE_PROTOCOL  99       /* Fake L4 Protocol to hide real protocol (TCP/UDP) */

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
    __u8 reserved;     /* Reserved for padding/alignment */
    __be64 seq;        /* Sequence number (dynamic part of IV) */
} __attribute__((packed));

/* ---- Generic Netlink Commands ---- */
enum mwan_genl_cmds {
    MWAN_CMD_UNSPEC = 0,
    MWAN_CMD_SET_CONFIG,  /* sdwan send to mwan_kmod */
    __MWAN_CMD_MAX,
};
#define MWAN_CMD_MAX (__MWAN_CMD_MAX - 1)

/* ---- Generic Netlink Attributes ---- */
enum mwan_genl_attrs {
    MWAN_ATTR_UNSPEC = 0,
    MWAN_ATTR_NODE_ID,    /* u32 */
    MWAN_ATTR_TUNNELS,    /* Nested array of tunnels */
    MWAN_ATTR_LOCAL_IP,   /* u32 (network byte order) */
    MWAN_ATTR_LOCAL_MASK, /* u32 (network byte order) */
    MWAN_ATTR_LOCAL_IFINDEX, /* u32 */
    MWAN_ATTR_ENCRYPT_ON,    /* u8: 0=off, 1=on */
    MWAN_ATTR_ENCRYPT_TYPE,  /* u8: enum mwan_crypt_type */
    MWAN_ATTR_ENCRYPT_KEY,   /* NLA_BINARY: raw key bytes (16 or 32) */
    MWAN_ATTR_ENCRYPT_SALT,  /* NLA_BINARY: 4 bytes salt */
    MWAN_ATTR_ENCRYPT_LAYER, /* u8: 2=L2 (MACsec), 3=L3 (Overlay) */
    __MWAN_ATTR_MAX,
};
#define MWAN_ATTR_MAX (__MWAN_ATTR_MAX - 1)

/* ---- Tunnel Sub-Attributes ---- */
enum mwan_tun_attrs {
    MWAN_TUN_UNSPEC = 0,
    MWAN_TUN_IFINDEX,     /* u32 */
    MWAN_TUN_WEIGHT,      /* u32 */
    MWAN_TUN_GATEWAY,     /* u32 (network byte order) */
    __MWAN_TUN_MAX,
};
#define MWAN_TUN_MAX (__MWAN_TUN_MAX - 1)

#endif /* MWAN_PROTO_H */

