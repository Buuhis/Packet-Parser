#include "kernel_sync.h"
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <arpa/inet.h>
#include "../kernel/mwan_proto.h"


int kernel_sync_push_config(const app_context_t *ctx) {
    struct nl_sock *sock;
    struct nl_msg *msg;
    int family_id, ret = -1;

    if (!ctx) return -1;

    log_info("Pushing configuration to mwan_kmod via Generic Netlink...");

    sock = nl_socket_alloc();
    if (!sock) return -1;
    
    if (genl_connect(sock) < 0) {
        log_error("Failed to connect to Generic Netlink");
        nl_socket_free(sock);
        return -1;
    }

    family_id = genl_ctrl_resolve(sock, MWAN_GENL_NAME);
    if (family_id < 0) {
        log_error("Kernel Module (mwan_kmod) not loaded or family not found");
        nl_socket_free(sock);
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(sock);
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0, MWAN_CMD_SET_CONFIG, MWAN_GENL_VERSION);

    nla_put_u32(msg, MWAN_ATTR_NODE_ID, ctx->cfg.node_id);
    
    /* Sync Local Network for Inbound Steering */
    if (ctx->cfg.local_ip > 0) {
        unsigned int local_idx = if_nametoindex(ctx->cfg.local_if);
        log_info("  [+] Sync Local Net: interface=%s (idx: %u)", ctx->cfg.local_if, local_idx);
        nla_put_u32(msg, MWAN_ATTR_LOCAL_IP, ctx->cfg.local_ip);
        nla_put_u32(msg, MWAN_ATTR_LOCAL_MASK, ctx->cfg.local_mask);
        nla_put_u32(msg, MWAN_ATTR_LOCAL_IFINDEX, local_idx);
    }

    struct nlattr *tunnels = nla_nest_start(msg, MWAN_ATTR_TUNNELS);
    for (size_t i = 0; i < ctx->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *tun = &ctx->cfg.sdwan_tuns[i];
        unsigned int idx = if_nametoindex(tun->ifname);
        if (idx == 0) continue;

        struct nlattr *tun_node = nla_nest_start(msg, i + 1);
        nla_put_u32(msg, MWAN_TUN_IFINDEX, idx);
        nla_put_u32(msg, MWAN_TUN_WEIGHT, tun->weight);
        
        struct in_addr gw_addr;
        if (inet_aton(tun->gateway, &gw_addr)) {
            nla_put_u32(msg, MWAN_TUN_GATEWAY, gw_addr.s_addr);
        }

        nla_nest_end(msg, tun_node);
        
        log_info("  [+] Sync Tunnel: %s (idx: %u, weight: %d, gw: %s)", 
                 tun->ifname, idx, tun->weight, tun->gateway);
    }
    nla_nest_end(msg, tunnels);

    /* Sync Encryption Config */
    if (ctx->cfg.encrypt.enabled) {
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_ON,   1);
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_LAYER, ctx->cfg.encrypt.layer);
        nla_put_u8(msg,  MWAN_ATTR_ENCRYPT_TYPE,  ctx->cfg.encrypt.type);
        nla_put(msg,     MWAN_ATTR_ENCRYPT_KEY,   ctx->cfg.encrypt.key_len, ctx->cfg.encrypt.key);
        nla_put(msg,     MWAN_ATTR_ENCRYPT_SALT,  MAX_ENCRYPT_SALT_LEN,     ctx->cfg.encrypt.salt);
        
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

    if (nl_send_auto(sock, msg) < 0) {
        log_error("Failed to send Netlink message");
    } else {
        log_info("Configuration pushed successfully to Kernel.");
        ret = 0;
    }

    nlmsg_free(msg);
    nl_socket_free(sock);
    return ret;
}

void kernel_sync_cleanup(void) {
    // Netlink is stateless for our SET_CONFIG pattern
}
