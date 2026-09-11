#include "kernel_sync.h"
#include "failover.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/socket.h>
#include "../kernel/mwan_proto.h"
#include "../sig_encrypt/inc/pqc_handshake.h"

struct tunnel_peer_reply {
    unsigned int expected_ifindex;
    struct in_addr peer_addr;
    bool resolved;
    bool received;
    bool valid;
};

struct tunnel_state_reply {
    unsigned int expected_ifindex;
    uint32_t generation;
    uint32_t sequence;
    bool up;
    bool received;
    bool valid;
};

struct pqc_key_state_reply {
    unsigned int expected_node_id;
    struct kernel_pqc_key_state state;
    bool received;
    bool valid;
};

static uint32_t active_kernel_config_generation;
static uint32_t pending_discovery_generation;

/* libnl normally returns its own NLE_* error namespace, while a Generic
 * Netlink error reply contains the real negative kernel errno.  Keep the
 * kernel errno when one is available and translate transport-side libnl
 * failures before returning them to CLI/failover callers. */
static int kernel_sync_nl_to_errno(int rc)
{
    if (rc >= 0)
        return rc;

    switch (-rc) {
    case NLE_INTR:
        return -EINTR;
    case NLE_BAD_SOCK:
        return -EBADF;
    case NLE_AGAIN:
        return -EAGAIN;
    case NLE_NOMEM:
        return -ENOMEM;
    case NLE_EXIST:
        return -EEXIST;
    case NLE_INVAL:
        return -EINVAL;
    case NLE_RANGE:
        return -ERANGE;
    case NLE_MSGSIZE:
    case NLE_MSG_TRUNC:
    case NLE_ATTRSIZE:
        return -EMSGSIZE;
    case NLE_OPNOTSUPP:
        return -EOPNOTSUPP;
    case NLE_AF_NOSUPPORT:
        return -EAFNOSUPPORT;
    case NLE_OBJ_NOTFOUND:
        return -ENOENT;
    case NLE_NOATTR:
        return -ENODATA;
    case NLE_MISSING_ATTR:
        return -EINVAL;
    case NLE_SEQ_MISMATCH:
    case NLE_PROTO_MISMATCH:
    case NLE_PARSE_ERR:
        return -EPROTO;
    case NLE_MSG_OVERFLOW:
        return -EOVERFLOW;
    case NLE_NOADDR:
        return -EADDRNOTAVAIL;
    case NLE_BUSY:
        return -EBUSY;
    case NLE_NOACCESS:
        return -EACCES;
    case NLE_PERM:
        return -EPERM;
    case NLE_NODEV:
        return -ENODEV;
    default:
        return -EIO;
    }
}

static int kernel_sync_nl_error_cb(struct sockaddr_nl *nla,
                                   struct nlmsgerr *error, void *arg)
{
    int *kernel_error = arg;

    (void)nla;
    if (!error) {
        if (kernel_error)
            *kernel_error = -EIO;
        return NL_STOP;
    }
    /* NLMSG_ERROR with error == 0 is a successful ACK, not a failure. */
    if (!error->error)
        return NL_OK;
    if (kernel_error)
        *kernel_error = error->error;
    return NL_STOP;
}

static int kernel_sync_tunnel_peer_valid_cb(struct nl_msg *msg, void *arg)
{
    struct tunnel_peer_reply *reply = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *ghdr = nlmsg_data(nlh);
    struct nlattr *attrs[MWAN_ATTR_MAX + 1] = {0};

    reply->received = true;
    if (!ghdr || ghdr->cmd != MWAN_CMD_GET_TUNNEL_PEERS ||
        genlmsg_parse(nlh, 0, attrs, MWAN_ATTR_MAX, NULL) < 0 ||
        !attrs[MWAN_ATTR_QUERY_IFINDEX] ||
        !attrs[MWAN_ATTR_PEER_RESOLVED] ||
        nla_get_u32(attrs[MWAN_ATTR_QUERY_IFINDEX]) !=
            reply->expected_ifindex)
        return NL_STOP;

    reply->resolved = nla_get_u8(attrs[MWAN_ATTR_PEER_RESOLVED]) != 0;
    if (!reply->resolved) {
        reply->valid = true;
        return NL_STOP;
    }
    if (!attrs[MWAN_ATTR_PEER_TUNNEL_IP] ||
        nla_len(attrs[MWAN_ATTR_PEER_TUNNEL_IP]) !=
            sizeof(reply->peer_addr.s_addr))
        return NL_STOP;

    memcpy(&reply->peer_addr.s_addr,
           nla_data(attrs[MWAN_ATTR_PEER_TUNNEL_IP]),
           sizeof(reply->peer_addr.s_addr));
    reply->valid = true;
    return NL_STOP;
}

static int kernel_sync_tunnel_state_valid_cb(struct nl_msg *msg, void *arg)
{
    struct tunnel_state_reply *reply = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *ghdr = nlmsg_data(nlh);
    struct nlattr *attrs[MWAN_ATTR_MAX + 1] = {0};

    reply->received = true;
    if (!ghdr || ghdr->cmd != MWAN_CMD_GET_TUNNEL_STATE ||
        genlmsg_parse(nlh, 0, attrs, MWAN_ATTR_MAX, NULL) < 0 ||
        !attrs[MWAN_ATTR_QUERY_IFINDEX] ||
        !attrs[MWAN_ATTR_CONFIG_GENERATION] ||
        !attrs[MWAN_ATTR_STATE_SEQUENCE] ||
        !attrs[MWAN_ATTR_TUNNEL_STATE] ||
        nla_get_u32(attrs[MWAN_ATTR_QUERY_IFINDEX]) !=
            reply->expected_ifindex ||
        nla_get_u8(attrs[MWAN_ATTR_TUNNEL_STATE]) > 1)
        return NL_STOP;

    reply->generation = nla_get_u32(attrs[MWAN_ATTR_CONFIG_GENERATION]);
    reply->sequence = nla_get_u32(attrs[MWAN_ATTR_STATE_SEQUENCE]);
    reply->up = nla_get_u8(attrs[MWAN_ATTR_TUNNEL_STATE]) != 0;
    reply->valid = true;
    return NL_STOP;
}

static int kernel_sync_pqc_key_state_valid_cb(struct nl_msg *msg, void *arg)
{
    struct pqc_key_state_reply *reply = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *ghdr = nlmsg_data(nlh);
    struct nlattr *attrs[MWAN_ATTR_MAX + 1] = {0};

    reply->received = true;
    if (!ghdr || ghdr->cmd != MWAN_CMD_GET_PQC_KEY_STATE ||
        genlmsg_parse(nlh, 0, attrs, MWAN_ATTR_MAX, NULL) < 0 ||
        !attrs[MWAN_ATTR_NODE_ID] ||
        !attrs[MWAN_ATTR_CONFIG_GENERATION] ||
        !attrs[MWAN_ATTR_REKEY_EPOCH] ||
        !attrs[MWAN_ATTR_KEY_STATE] || !attrs[MWAN_ATTR_KEY_ID] ||
        nla_get_u32(attrs[MWAN_ATTR_NODE_ID]) != reply->expected_node_id)
        return NL_STOP;

    reply->state.generation =
        nla_get_u32(attrs[MWAN_ATTR_CONFIG_GENERATION]);
    reply->state.epoch = nla_get_u64(attrs[MWAN_ATTR_REKEY_EPOCH]);
    reply->state.state = nla_get_u8(attrs[MWAN_ATTR_KEY_STATE]);
    reply->state.current_id = nla_get_u8(attrs[MWAN_ATTR_KEY_ID]);
    reply->state.prev_id = attrs[MWAN_ATTR_PREV_KEY_ID] ?
        nla_get_u8(attrs[MWAN_ATTR_PREV_KEY_ID]) : 0;
    reply->state.next_id = attrs[MWAN_ATTR_NEXT_KEY_ID] ?
        nla_get_u8(attrs[MWAN_ATTR_NEXT_KEY_ID]) : 0;
    reply->valid = true;
    return NL_STOP;
}

static int kernel_sync_register_pending_discovery(const app_context_t *ctx,
                                                  uint32_t *generation_out)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    struct nlattr *tunnels;
    uint32_t counter;
    uint32_t generation;
    int family_id;
    int ret = -EIO;
    size_t i;

    if (!ctx || !generation_out || ctx->cfg.node_id <= 0 ||
        ctx->cfg.sdwan_tun_count > MAX_SDWAN_TUNS)
        return -EINVAL;

    counter = __atomic_add_fetch(&pending_discovery_generation, 1,
                                 __ATOMIC_RELAXED) &
              ~MWAN_DISCOVERY_GENERATION_FLAG;
    if (!counter)
        counter = __atomic_add_fetch(&pending_discovery_generation, 1,
                                     __ATOMIC_RELAXED) &
                  ~MWAN_DISCOVERY_GENERATION_FLAG;
    generation = counter | MWAN_DISCOVERY_GENERATION_FLAG;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    ret = genl_connect(sock);
    if (ret < 0) {
        ret = kernel_sync_nl_to_errno(ret);
        goto out;
    }
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = kernel_sync_nl_to_errno(family_id);
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_SET_DISCOVERY_CONFIG, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_NODE_ID,
                    (uint32_t)ctx->cfg.node_id) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    tunnels = nla_nest_start(msg, MWAN_ATTR_TUNNELS);
    if (!tunnels) {
        ret = -EMSGSIZE;
        goto out;
    }
    for (i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &ctx->cfg.sdwan_tuns[i];
        struct nlattr *tun_node;
        unsigned int ifindex = if_nametoindex(tun->tunnel_ifname);

        if (!ifindex) {
            ret = -ENODEV;
            goto out;
        }
        tun_node = nla_nest_start(msg, (int)i + 1);
        if (!tun_node ||
            nla_put_u32(msg, MWAN_TUN_IFINDEX, ifindex) < 0) {
            ret = -EMSGSIZE;
            goto out;
        }
        nla_nest_end(msg, tun_node);
    }
    nla_nest_end(msg, tunnels);

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        ret = kernel_sync_nl_to_errno(ret);
        goto out;
    }
    ret = nl_wait_for_ack(sock);
    if (ret < 0) {
        ret = kernel_sync_nl_to_errno(ret);
        goto out;
    }
    *generation_out = generation;
    log_info("[DISCOVERY-CONFIG] registered pending control-plane node=%d generation=%u tunnels=%zu datapath_active=0",
             ctx->cfg.node_id, generation, ctx->cfg.sdwan_tun_count);
    ret = 0;
out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}


enum kernel_sync_result kernel_sync_push_config(const app_context_t *ctx) {
    struct nl_sock *sock;
    struct nl_msg *msg;
    static unsigned long push_generation;
    static uint32_t config_generation;
    unsigned long push_id;
    uint32_t generation;
    unsigned int nl_seq = 0;
    int family_id;
    enum kernel_sync_result ret = KERNEL_SYNC_ERROR;
    int send_ret;
    int ack_ret;
    uint8_t pqc_keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ] = {{0}};
    uint8_t pqc_key_ids[KEY_SLOT_COUNT] = {0};
    bool pqc_slots_valid[KEY_SLOT_COUNT] = {false};
    bool have_pqc_slots = false;

    if (!ctx) return KERNEL_SYNC_ERROR;

    push_id = __atomic_add_fetch(&push_generation, 1, __ATOMIC_RELAXED);
    log_info("[CFG-TRACE push=%lu] PREPARE node=%d enabled=%d layer=%u type=%u key_len=%zu tunnels=%zu",
             push_id, ctx->cfg.node_id, ctx->cfg.encrypt.enabled,
             ctx->cfg.encrypt.layer, ctx->cfg.encrypt.type,
             ctx->cfg.encrypt.key_len, ctx->cfg.sdwan_tun_count);

    /* A PQC profile is loaded before its authenticated handshake completes.
     * Do not send the DB key (or a zero-length key) to the kernel.  The
     * sig_pqc_on_key_ready() callback will push this config after installing
     * the derived 32-byte traffic key in the userspace context. */
    if (ctx->cfg.encrypt.enabled &&
        ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM &&
        ctx->cfg.encrypt.key_len != 32) {
        uint32_t discovery_generation = 0;
        int discovery_ret = kernel_sync_register_pending_discovery(
            ctx, &discovery_generation);

        if (discovery_ret) {
            log_error("[CFG-TRACE push=%lu] DISCOVERY_REGISTER_FAILED error=%s",
                      push_id, strerror(-discovery_ret));
            return KERNEL_SYNC_ERROR;
        }
        /* On initial activation there is no datapath to protect, so BFD may
         * run entirely against pending state. During a re-handshake, keep the
         * existing active BFD sessions untouched until the new full config is
         * ready; otherwise a pending generation could disrupt healthy paths. */
        if (__atomic_load_n(&active_kernel_config_generation,
                            __ATOMIC_ACQUIRE) == 0) {
            (void)failover_service_reconcile(ctx, discovery_generation);
        } else {
            log_info("[DISCOVERY-CONFIG] active datapath generation=%u preserved while pending generation=%u waits for PQC key",
                     __atomic_load_n(&active_kernel_config_generation,
                                     __ATOMIC_ACQUIRE),
                     discovery_generation);
        }
        log_info("[CFG-TRACE push=%lu] DEFERRED reason=PQC_KEY_NOT_READY key_len=%zu (active SET_CONFIG not sent)",
                 push_id, ctx->cfg.encrypt.key_len);
        return KERNEL_SYNC_DEFERRED;
    }

    generation = __atomic_add_fetch(&config_generation, 1,
                                    __ATOMIC_RELAXED) &
                 ~MWAN_DISCOVERY_GENERATION_FLAG;
    if (generation == 0)
        generation = __atomic_add_fetch(&config_generation, 1,
                                        __ATOMIC_RELAXED) &
                     ~MWAN_DISCOVERY_GENERATION_FLAG;

    if (ctx->cfg.encrypt.enabled &&
        ctx->cfg.encrypt.type == MWAN_CRYPT_PQC_GCM &&
        sig_pqc_snapshot_keys(ctx->cfg.node_id, pqc_keys, pqc_key_ids,
                              pqc_slots_valid) == 0 &&
        pqc_slots_valid[KEY_SLOT_CURRENT] &&
        pqc_key_ids[KEY_SLOT_CURRENT] != 0 &&
        memcmp(pqc_keys[KEY_SLOT_CURRENT], ctx->cfg.encrypt.key,
               PQC_TRAFFIC_KEY_SZ) == 0) {
        have_pqc_slots = true;
    }

    log_info("Pushing configuration to mwan_kmod via Generic Netlink...");

    sock = nl_socket_alloc();
    if (!sock) return KERNEL_SYNC_ERROR;
    
    if (genl_connect(sock) < 0) {
        log_error("Failed to connect to Generic Netlink");
        nl_socket_free(sock);
        return KERNEL_SYNC_ERROR;
    }

    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        log_error("Kernel Module (mwan_kmod) not loaded or family not found");
        nl_socket_free(sock);
        return KERNEL_SYNC_ERROR;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(sock);
        return KERNEL_SYNC_ERROR;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0, MWAN_CMD_SET_CONFIG, MWAN_GENL_VERSION);

    nla_put_u32(msg, MWAN_ATTR_NODE_ID, ctx->cfg.node_id);
    nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation);
    
    struct nlattr *tunnels = nla_nest_start(msg, MWAN_ATTR_TUNNELS);
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &ctx->cfg.sdwan_tuns[i];
        unsigned int idx = if_nametoindex(tun->tunnel_ifname);
        if (idx == 0) {
            log_error("Tunnel interface '%s' does not exist",
                      tun->tunnel_ifname);
            goto out;
        }

        struct nlattr *tun_node = nla_nest_start(msg, i + 1);
        nla_put_u32(msg, MWAN_TUN_IFINDEX, idx);
        nla_put_u32(msg, MWAN_TUN_WEIGHT, tun->weight);

        nla_nest_end(msg, tun_node);
        
        log_info("[CFG-TRACE push=%lu] TUNNEL slot=%zu name=%s ifindex=%u physical=%s weight=%d",
                 push_id, i, tun->tunnel_ifname, idx,
                 tun->physical_ifname, tun->weight);
    }
    nla_nest_end(msg, tunnels);

    /* Sync Encryption Config */
    if (ctx->cfg.encrypt.enabled) {
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_ON,   1);
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_LAYER, ctx->cfg.encrypt.layer);
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_TYPE,  ctx->cfg.encrypt.type);
        nla_put(msg,     MWAN_ATTR_ENCRYPT_KEY,   ctx->cfg.encrypt.key_len, ctx->cfg.encrypt.key);
        nla_put(msg,     MWAN_ATTR_ENCRYPT_SALT,  MAX_ENCRYPT_SALT_LEN,     ctx->cfg.encrypt.salt);
        if (have_pqc_slots) {
            nla_put_u8(msg, MWAN_ATTR_KEY_ID,
                       pqc_key_ids[KEY_SLOT_CURRENT]);
            if (pqc_slots_valid[KEY_SLOT_PREV] &&
                pqc_key_ids[KEY_SLOT_PREV] != 0 &&
                pqc_key_ids[KEY_SLOT_PREV] !=
                    pqc_key_ids[KEY_SLOT_CURRENT]) {
                nla_put(msg, MWAN_ATTR_PREV_KEY, PQC_TRAFFIC_KEY_SZ,
                        pqc_keys[KEY_SLOT_PREV]);
                nla_put_u8(msg, MWAN_ATTR_PREV_KEY_ID,
                           pqc_key_ids[KEY_SLOT_PREV]);
            }
        } else {
            nla_put_u8(msg, MWAN_ATTR_KEY_ID, 1);
        }
        
        const char *type_str = "AES-GCM-128";
        if (ctx->cfg.encrypt.type == 1) type_str = "AES-GCM-256";
        else if (ctx->cfg.encrypt.type == 2) type_str = "PQC-GCM";

        log_info("  [+] Sync Encryption: ON (layer: %u, type: %s, key_len: %zu)",
                 ctx->cfg.encrypt.layer,
                 type_str,
                 ctx->cfg.encrypt.key_len);
    } else {
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_ON,   0);
        log_info("  [+] Sync Encryption: OFF");
    }

    send_ret = nl_send_auto(sock, msg);
    nl_seq = nlmsg_hdr(msg)->nlmsg_seq;
    if (send_ret < 0) {
        log_error("[CFG-TRACE push=%lu nlseq=%u] SEND_FAILED err=%d (%s)",
                  push_id, nl_seq, send_ret, nl_geterror(send_ret));
        goto out;
    }

    log_info("[CFG-TRACE push=%lu nlseq=%u] SENT bytes=%d waiting_for_kernel_ack=1",
             push_id, nl_seq, send_ret);
    ack_ret = nl_wait_for_ack(sock);
    if (ack_ret < 0) {
        log_error("[CFG-TRACE push=%lu nlseq=%u] KERNEL_REJECTED err=%d (%s)",
                  push_id, nl_seq, ack_ret, nl_geterror(ack_ret));
        goto out;
    }

    __atomic_store_n(&active_kernel_config_generation, generation,
                     __ATOMIC_RELEASE);

    log_info("[CFG-TRACE push=%lu nlseq=%u] KERNEL_ACK_OK node=%d enabled=%d layer=%u type=%u key_len=%zu tunnels=%zu",
             push_id, nl_seq, ctx->cfg.node_id, ctx->cfg.encrypt.enabled,
             ctx->cfg.encrypt.layer, ctx->cfg.encrypt.type,
             ctx->cfg.encrypt.key_len, ctx->cfg.sdwan_tun_count);
    ret = KERNEL_SYNC_APPLIED;
    (void)failover_service_reconcile(ctx, generation);

out:
    nlmsg_free(msg);
    nl_socket_free(sock);
    return ret;
}

uint32_t kernel_sync_current_config_generation(void)
{
    return __atomic_load_n(&active_kernel_config_generation,
                           __ATOMIC_ACQUIRE);
}

int kernel_sync_update_tunnel_weights(const app_context_t *ctx)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    struct nlattr *tunnels;
    uint32_t generation = kernel_sync_current_config_generation();
    int family_id;
    int ret = -EIO;
    size_t i;

    if (!ctx || ctx->cfg.node_id <= 0 || !generation ||
        ctx->cfg.sdwan_tun_count == 0)
        return -EINVAL;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    if (genl_connect(sock) < 0)
        goto out;
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_SET_TUNNEL_WEIGHTS, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_NODE_ID,
                    (uint32_t)ctx->cfg.node_id) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }

    tunnels = nla_nest_start(msg, MWAN_ATTR_TUNNELS);
    if (!tunnels) {
        ret = -EMSGSIZE;
        goto out;
    }
    for (i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &ctx->cfg.sdwan_tuns[i];
        struct nlattr *tun_node;
        unsigned int ifindex;

        ifindex = if_nametoindex(tun->tunnel_ifname);
        if (!ifindex || tun->weight <= 0) {
            ret = ifindex ? -EINVAL : -ENODEV;
            goto out;
        }
        tun_node = nla_nest_start(msg, (int)i + 1);
        if (!tun_node ||
            nla_put_u32(msg, MWAN_TUN_IFINDEX, ifindex) < 0 ||
            nla_put_u32(msg, MWAN_TUN_WEIGHT,
                        (uint32_t)tun->weight) < 0) {
            ret = -EMSGSIZE;
            goto out;
        }
        nla_nest_end(msg, tun_node);
    }
    nla_nest_end(msg, tunnels);

    ret = nl_send_auto(sock, msg);
    if (ret >= 0)
        ret = nl_wait_for_ack(sock);
    if (ret >= 0) {
        log_info("[WEIGHT-UPDATE] profile=%d generation=%u tunnels=%zu runtime_preserved=1",
                 ctx->cfg.node_id, generation,
                 ctx->cfg.sdwan_tun_count);
        ret = 0;
    }

out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

static int kernel_sync_pqc_key_command(uint8_t command, int profile_id,
                                       uint64_t epoch, uint8_t key_id,
                                       const uint8_t *key)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    uint32_t generation = kernel_sync_current_config_generation();
    int family_id;
    int ret = -EIO;

    if (profile_id <= 0 || !generation || !key_id ||
        (!epoch && command != MWAN_CMD_RETIRE_PQC_KEY))
        return -EINVAL;
    if (command == MWAN_CMD_STAGE_PQC_KEY && !key)
        return -EINVAL;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    if (genl_connect(sock) < 0)
        goto out;
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     command, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_NODE_ID, (uint32_t)profile_id) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation) < 0 ||
        nla_put_u64(msg, MWAN_ATTR_REKEY_EPOCH, epoch) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    if (command == MWAN_CMD_RETIRE_PQC_KEY) {
        if (nla_put_u8(msg, MWAN_ATTR_PREV_KEY_ID, key_id) < 0) {
            ret = -EMSGSIZE;
            goto out;
        }
    } else if (nla_put_u8(msg, MWAN_ATTR_NEXT_KEY_ID, key_id) < 0 ||
               (command == MWAN_CMD_STAGE_PQC_KEY &&
                nla_put(msg, MWAN_ATTR_NEXT_KEY, PQC_TRAFFIC_KEY_SZ,
                        key) < 0)) {
        ret = -EMSGSIZE;
        goto out;
    }
    ret = nl_send_auto(sock, msg);
    if (ret >= 0)
        ret = nl_wait_for_ack(sock);
    if (ret >= 0)
        ret = 0;
out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

int kernel_sync_stage_pqc_key(int profile_id, uint64_t epoch, uint8_t key_id,
                              const uint8_t key[PQC_TRAFFIC_KEY_SZ])
{
    return kernel_sync_pqc_key_command(MWAN_CMD_STAGE_PQC_KEY, profile_id,
                                       epoch, key_id, key);
}

int kernel_sync_activate_pqc_key(int profile_id, uint64_t epoch,
                                 uint8_t key_id)
{
    return kernel_sync_pqc_key_command(MWAN_CMD_ACTIVATE_PQC_KEY, profile_id,
                                       epoch, key_id, NULL);
}

int kernel_sync_retire_pqc_key(int profile_id, uint64_t epoch,
                               uint8_t key_id)
{
    return kernel_sync_pqc_key_command(MWAN_CMD_RETIRE_PQC_KEY, profile_id,
                                       epoch, key_id, NULL);
}

int kernel_sync_abort_pqc_key(int profile_id, uint64_t epoch,
                              uint8_t key_id)
{
    return kernel_sync_pqc_key_command(MWAN_CMD_ABORT_PQC_KEY, profile_id,
                                       epoch, key_id, NULL);
}

int kernel_sync_get_pqc_key_state(int profile_id,
                                  struct kernel_pqc_key_state *state)
{
    struct pqc_key_state_reply reply = {0};
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    int family_id;
    int ret = -EIO;

    if (profile_id <= 0 || !state)
        return -EINVAL;
    reply.expected_node_id = (unsigned int)profile_id;
    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    if (genl_connect(sock) < 0)
        goto out;
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_GET_PQC_KEY_STATE, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_NODE_ID, (uint32_t)profile_id) < 0 ||
        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                            kernel_sync_pqc_key_state_valid_cb,
                            &reply) < 0 ||
        nl_send_auto(sock, msg) < 0 || nl_recvmsgs_default(sock) < 0)
        goto out;
    if (!reply.received || !reply.valid) {
        ret = -EPROTO;
        goto out;
    }
    *state = reply.state;
    ret = 0;
out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

int kernel_sync_set_tunnel_state_by_ifindex(unsigned int ifindex,
                                            uint32_t generation,
                                            uint32_t sequence, bool up)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    int family_id;
    int ret = -EIO;

    if (ifindex == 0 || generation == 0 || sequence == 0)
        return -EINVAL;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    if (genl_connect(sock) < 0)
        goto out;
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_SET_TUNNEL_STATE, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_QUERY_IFINDEX, ifindex) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_STATE_SEQUENCE, sequence) < 0 ||
        nla_put_u8(msg, MWAN_ATTR_TUNNEL_STATE, up ? 1 : 0) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    ret = nl_send_auto(sock, msg);
    if (ret >= 0)
        ret = nl_wait_for_ack(sock);
    if (ret >= 0)
        ret = 0;

out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

int kernel_sync_set_tunnel_state(const char *ifname, uint32_t generation,
                                 uint32_t sequence, bool up)
{
    unsigned int ifindex;

    if (!ifname || !ifname[0])
        return -EINVAL;
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -ENODEV;
    return kernel_sync_set_tunnel_state_by_ifindex(
        ifindex, generation, sequence, up);
}

int kernel_sync_get_tunnel_state_by_ifindex(
    unsigned int ifindex, struct kernel_tunnel_state *state)
{
    struct tunnel_state_reply reply = {0};
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    int kernel_error = 0;
    int family_id;
    int nl_rc;
    int ret = -EIO;

    if (ifindex == 0 || !state)
        return -EINVAL;
    reply.expected_ifindex = ifindex;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    nl_rc = genl_connect(sock);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = kernel_sync_nl_to_errno(family_id);
        if (ret == -ENOENT)
            ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_GET_TUNNEL_STATE, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_QUERY_IFINDEX, ifindex) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    nl_rc = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                               kernel_sync_tunnel_state_valid_cb, &reply);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_socket_modify_err_cb(sock, NL_CB_CUSTOM,
                                    kernel_sync_nl_error_cb,
                                    &kernel_error);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_send_auto(sock, msg);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_recvmsgs_default(sock);
    if (kernel_error) {
        ret = kernel_error;
        goto out;
    }
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    if (!reply.received || !reply.valid) {
        ret = -EPROTO;
        goto out;
    }
    state->generation = reply.generation;
    state->sequence = reply.sequence;
    state->up = reply.up;
    ret = 0;

out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

int kernel_sync_get_tunnel_status(const char *ifname, bool *up)
{
    struct kernel_tunnel_state state;
    unsigned int ifindex;
    int ret;

    if (!ifname || !ifname[0] || !up)
        return -EINVAL;
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -ENODEV;
    ret = kernel_sync_get_tunnel_state_by_ifindex(ifindex, &state);
    if (!ret)
        *up = state.up;
    return ret;
}

int kernel_sync_rebind_tunnel(int node_id, uint32_t generation,
                              unsigned int old_ifindex,
                              unsigned int new_ifindex)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    int family_id;
    int ret = -EIO;

    if (node_id <= 0 || !generation || !old_ifindex || !new_ifindex)
        return -EINVAL;
    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    if (genl_connect(sock) < 0)
        goto out;
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = -ENODEV;
        goto out;
    }
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_REBIND_TUNNEL, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_NODE_ID, (uint32_t)node_id) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_CONFIG_GENERATION, generation) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_QUERY_IFINDEX, old_ifindex) < 0 ||
        nla_put_u32(msg, MWAN_ATTR_NEW_IFINDEX, new_ifindex) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    ret = nl_send_auto(sock, msg);
    if (ret >= 0)
        ret = nl_wait_for_ack(sock);
    if (ret >= 0)
        ret = 0;
out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

int kernel_sync_get_tunnel_peer(const char *ifname, char *peer_ip,
                                size_t peer_ip_len)
{
    struct tunnel_peer_reply reply = {0};
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    unsigned int ifindex;
    int kernel_error = 0;
    int family_id;
    int nl_rc;
    int ret = -EIO;

    if (!ifname || !ifname[0] || !peer_ip || peer_ip_len == 0)
        return -EINVAL;
    peer_ip[0] = '\0';
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -ENODEV;
    reply.expected_ifindex = ifindex;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;
    nl_rc = genl_connect(sock);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        ret = kernel_sync_nl_to_errno(family_id);
        if (ret == -ENOENT)
            ret = -ENODEV;
        goto out;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                     MWAN_CMD_GET_TUNNEL_PEERS, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_QUERY_IFINDEX, ifindex) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    nl_rc = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                               kernel_sync_tunnel_peer_valid_cb, &reply);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_socket_modify_err_cb(sock, NL_CB_CUSTOM,
                                    kernel_sync_nl_error_cb,
                                    &kernel_error);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_send_auto(sock, msg);
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }
    nl_rc = nl_recvmsgs_default(sock);
    if (kernel_error) {
        ret = kernel_error;
        goto out;
    }
    if (nl_rc < 0) {
        ret = kernel_sync_nl_to_errno(nl_rc);
        goto out;
    }

    if (!reply.received || !reply.valid) {
        ret = -EPROTO;
        goto out;
    }
    if (!reply.resolved) {
        ret = -EAGAIN;
        goto out;
    }
    if (!inet_ntop(AF_INET, &reply.peer_addr, peer_ip, peer_ip_len)) {
        ret = -errno;
        goto out;
    }
    ret = 0;

out:
    if (msg)
        nlmsg_free(msg);
    if (sock)
        nl_socket_free(sock);
    return ret;
}

void kernel_sync_cleanup(void) {
    // Netlink is stateless for our SET_CONFIG pattern
}
