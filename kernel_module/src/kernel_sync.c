#include "kernel_sync.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "../kernel/mwan_proto.h"
#include "../sig_encrypt/inc/pqc_handshake.h"

struct tunnel_peer_reply {
    unsigned int expected_ifindex;
    struct in_addr peer_addr;
    bool resolved;
    bool received;
    bool valid;
};

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


enum kernel_sync_result kernel_sync_push_config(const app_context_t *ctx) {
    struct nl_sock *sock;
    struct nl_msg *msg;
    static unsigned long push_generation;
    unsigned long push_id;
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
        log_info("[CFG-TRACE push=%lu] DEFERRED reason=PQC_KEY_NOT_READY key_len=%zu (no Netlink message sent)",
                 push_id, ctx->cfg.encrypt.key_len);
        return KERNEL_SYNC_DEFERRED;
    }

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

    log_info("[CFG-TRACE push=%lu nlseq=%u] KERNEL_ACK_OK node=%d enabled=%d layer=%u type=%u key_len=%zu tunnels=%zu",
             push_id, nl_seq, ctx->cfg.node_id, ctx->cfg.encrypt.enabled,
             ctx->cfg.encrypt.layer, ctx->cfg.encrypt.type,
             ctx->cfg.encrypt.key_len, ctx->cfg.sdwan_tun_count);
    ret = KERNEL_SYNC_APPLIED;

out:
    nlmsg_free(msg);
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
    int family_id;
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
                     MWAN_CMD_GET_TUNNEL_PEERS, MWAN_GENL_VERSION) ||
        nla_put_u32(msg, MWAN_ATTR_QUERY_IFINDEX, ifindex) < 0) {
        ret = -EMSGSIZE;
        goto out;
    }
    if (nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                            kernel_sync_tunnel_peer_valid_cb,
                            &reply) < 0 ||
        nl_send_auto(sock, msg) < 0 || nl_recvmsgs_default(sock) < 0)
        goto out;

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
