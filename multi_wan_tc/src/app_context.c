#include "app_context.h"
#include "utils/logger.h"
#include "config/config_parser.h"
#include "system/system.h"

#include <string.h>

static int mac_is_all_zero(const unsigned char mac[6])
{
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0)
            return 0;
    }
    return 1;
}

static void mac_to_str(const unsigned char mac[6], char out[18])
{
    /* "aa:bb:cc:dd:ee:ff" + '\0' => 18 */
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * RX-A0: prepare runtime state (cache MACs, validate config)
 * - MUST run once at init, not in fast-path
 */
static int rx_prepare(app_context_t *ctx)
{
    /* 1) Validate LAN dst_mac (used when forwarding WAN->LOCAL) */
    if (mac_is_all_zero(ctx->cfg.lan.dst_mac)) {
        log_error("LAN_DST_MAC is invalid (all zeros). Please set *_LAN_DST_MAC in config.env");
        return -1;
    }

    /* 2) Cache local_if MAC into lan.src_mac */
    if (system_get_if_hwaddr(ctx->cfg.local_if, ctx->cfg.lan.src_mac) != 0) {
        log_error("Failed to get MAC of local_if '%s'", ctx->cfg.local_if);
        return -1;
    }

    /* 3) Validate WAN entries and cache each wan src_mac */
    if (ctx->cfg.wan_count == 0 || ctx->cfg.wan_count > MAX_WANS) {
        log_error("Invalid WAN count: %zu", ctx->cfg.wan_count);
        return -1;
    }

    for (size_t i = 0; i < ctx->cfg.wan_count; i++) {
        wan_cfg_t *w = &ctx->cfg.wans[i];

        if (w->ifname[0] == '\0') {
            log_error("WAN[%zu] ifname is empty", i);
            return -1;
        }

        if (mac_is_all_zero(w->dst_mac)) {
            log_error("WAN[%zu] DST_MAC is invalid (all zeros). Please set *_WANS_%zu_DST_MAC", i, i);
            return -1;
        }

        if (system_get_if_hwaddr(w->ifname, w->src_mac) != 0) {
            log_error("Failed to get MAC of WAN[%zu] if '%s'", i, w->ifname);
            return -1;
        }
    }

    /* 4) Optional: cache NE tunnel src_mac (if you use them like real netdevs) */
    if (ctx->cfg.ne_tunnel_count > MAX_NE_TUNNELS) {
        log_error("Invalid NE_TUNNEL count: %zu", ctx->cfg.ne_tunnel_count);
        return -1;
    }

    for (size_t i = 0; i < ctx->cfg.ne_tunnel_count; i++) {
        ne_tunnel_cfg_t *t = &ctx->cfg.ne_tunnels[i];

        if (t->ifname[0] == '\0') {
            log_error("NE_TUNNEL[%zu] ifname is empty", i);
            return -1;
        }

        /* dst_mac may be optional depending on your design; if required, validate */
        if (mac_is_all_zero(t->dst_mac)) {
            log_error("NE_TUNNEL[%zu] DST_MAC is invalid (all zeros). Please set *_NE_TUNNEL_%zu_DST_MAC", i, i);
            return -1;
        }

        /* Only cache src_mac if the netdev exists now; if it may appear later, you can relax this */
        if (system_get_if_hwaddr(t->ifname, t->src_mac) != 0) {
            log_error("Failed to get MAC of NE_TUNNEL[%zu] if '%s'", i, t->ifname);
            return -1;
        }
    }

    /* 5) Log summary (helpful for bring-up) */
    char mac_local_src[18], mac_lan_dst[18];
    mac_to_str(ctx->cfg.lan.src_mac, mac_local_src);
    mac_to_str(ctx->cfg.lan.dst_mac, mac_lan_dst);
    log_info("RX-A0: local_if=%s src_mac=%s, lan dst_mac=%s",
             ctx->cfg.local_if, mac_local_src, mac_lan_dst);

    for (size_t i = 0; i < ctx->cfg.wan_count; i++) {
        char s[18], d[18];
        mac_to_str(ctx->cfg.wans[i].src_mac, s);
        mac_to_str(ctx->cfg.wans[i].dst_mac, d);
        log_info("RX-A0: WAN[%zu] if=%s src_mac=%s dst_mac=%s weight=%d",
                 i, ctx->cfg.wans[i].ifname, s, d, ctx->cfg.wans[i].weight);
    }

    return 0;
}

int app_context_init(app_context_t *ctx,
                     const char *config_path,
                     const char *node_id)
{
    memset(ctx, 0, sizeof(*ctx));

    /* Load config (.env) into ctx->cfg */
    if (config_load_env(config_path, node_id, &ctx->cfg) != 0) {
        log_error("Failed to load env config for node '%s'", node_id);
        return -1;
    }

    strncpy(ctx->cfg.node_id, node_id, sizeof(ctx->cfg.node_id) - 1);

    /* Basic validation */
    if (ctx->cfg.local_if[0] == '\0') {
        log_error("LOCAL_IF is missing for node '%s'", node_id);
        return -1;
    }
    if (ctx->cfg.remote_cidr[0] == '\0') {
        log_error("REMOTE_CIDR is missing for node '%s'", node_id);
        return -1;
    }

    /* Dataplane names unified */
    if (ctx->cfg.dataplane.veth_in[0] == '\0' ||
        ctx->cfg.dataplane.veth_out[0] == '\0') {
        log_error("DATAPLANE_VETH_IN/OUT is missing for node '%s'", node_id);
        return -1;
    }
    if (ctx->cfg.dataplane.mtu <= 0) {
        ctx->cfg.dataplane.mtu = 1500;
    }

    /* ---- RX: cache MACs + validate MACs (critical for SOCK_RAW L2 forward) ---- */
    if (rx_prepare(ctx) != 0) {
        log_error("RX prepare failed for node '%s'", node_id);
        return -1;
    }

    return 0;
}

void app_context_dump(const app_context_t *ctx)
{
    log_info("Node: %s", ctx->cfg.node_id);
    log_info("Local IF: %s", ctx->cfg.local_if);
    log_info("Remote CIDR: %s", ctx->cfg.remote_cidr);
    log_info("WAN count: %zu", ctx->cfg.wan_count);
}
