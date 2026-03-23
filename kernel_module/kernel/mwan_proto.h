#ifndef MWAN_PROTO_H
#define MWAN_PROTO_H

#define MWAN_GENL_NAME "MWAN_STEER"
#define MWAN_GENL_VERSION 1

enum mwan_genl_cmds {
    MWAN_CMD_UNSPEC = 0,
    MWAN_CMD_SET_CONFIG,  /* sep-wan sends to mwan_kmod */
    __MWAN_CMD_MAX,
};
#define MWAN_CMD_MAX (__MWAN_CMD_MAX - 1)

enum mwan_genl_attrs {
    MWAN_ATTR_UNSPEC = 0,
    MWAN_ATTR_NODE_ID,    /* u32 */
    MWAN_ATTR_CIDR_IP,    /* u32 (network byte order) */
    MWAN_ATTR_CIDR_MASK,  /* u32 (network byte order) */
    MWAN_ATTR_TUNNELS,    /* Nested array of tunnels */
    __MWAN_ATTR_MAX,
};
#define MWAN_ATTR_MAX (__MWAN_ATTR_MAX - 1)

enum mwan_tun_attrs {
    MWAN_TUN_UNSPEC = 0,
    MWAN_TUN_IFINDEX,     /* u32 */
    MWAN_TUN_WEIGHT,      /* u32 */
    __MWAN_TUN_MAX,
};
#define MWAN_TUN_MAX (__MWAN_TUN_MAX - 1)

#endif /* MWAN_PROTO_H */
