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

/* Helper to parse CIDR "192.168.182.0/24" into numeric IP and bitmask */
static void parse_cidr(const char *cidr, uint32_t *ip, uint32_t *mask) {
    char buf[32];
    strncpy(buf, cidr, sizeof(buf)-1);
    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }
    struct in_addr addr;
    inet_aton(buf, &addr);
    *ip = addr.s_addr;
    *mask = (prefix == 0) ? 0 : htonl(~((1U << (32 - prefix)) - 1));
}

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

    uint32_t ip, mask;
    parse_cidr(ctx->cfg.remote_cidr, &ip, &mask);

    nla_put_u32(msg, MWAN_ATTR_NODE_ID, ctx->cfg.node_id);
    nla_put_u32(msg, MWAN_ATTR_CIDR_IP, ip);
    nla_put_u32(msg, MWAN_ATTR_CIDR_MASK, mask);

    struct nlattr *tunnels = nla_nest_start(msg, MWAN_ATTR_TUNNELS);
    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        const ne_tunnel_cfg_t *tun = &ctx->cfg.ne_tunnels[i];
        unsigned int idx = if_nametoindex(tun->ifname);
        if (idx == 0) continue;

        struct nlattr *tun_node = nla_nest_start(msg, i + 1);
        nla_put_u32(msg, MWAN_TUN_IFINDEX, idx);
        nla_put_u32(msg, MWAN_TUN_WEIGHT, tun->weight);
        nla_nest_end(msg, tun_node);
        
        log_info("  [+] Sync Tunnel: %s (idx: %u, weight: %d)", tun->ifname, idx, tun->weight);
    }
    nla_nest_end(msg, tunnels);

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
