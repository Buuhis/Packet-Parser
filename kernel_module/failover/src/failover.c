#define _GNU_SOURCE
#include "failover.h"
#include "utils/logger.h"
#include "../../kernel/mwan_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FAILOVER_RECONCILE_MS 500U
#define FAILOVER_BFD_INTERVAL_US 300000U
#define FAILOVER_BFD_DETECT_MULT 3U

struct failover_tunnel_config {
    unsigned int ifindex;
    char ifname[IFNAMSIZ];
    struct in_addr local_ip;
};

struct failover_snapshot {
    int node_id;
    size_t count;
    struct failover_tunnel_config tunnels[MAX_SDWAN_TUNS];
};

struct failover_peer {
    unsigned int ifindex;
    unsigned int configured_ifindex;
    char ifname[IFNAMSIZ];
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint32_t generation;
    uint32_t state_sequence;
    bool resolved;
};

struct failover_peer_list {
    uint32_t node_id;
    size_t count;
    struct failover_peer peers[MAX_SDWAN_TUNS];
};

struct failover_runtime_entry {
    unsigned int ifindex;
    unsigned int configured_ifindex;
    char ifname[IFNAMSIZ];
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint32_t peer_generation;
    uint32_t state_sequence;
};

struct failover_service {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t thread;
    bool started;
    bool stop;
    bool cleanup_registered;
    uint64_t desired_generation;
    struct failover_snapshot desired;
};

static struct failover_service service = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static struct failover_runtime_entry runtime[MAX_SDWAN_TUNS];
static size_t runtime_count;

static int parse_local_ipv4(const char *text, struct in_addr *address)
{
    char buffer[INET_ADDRSTRLEN];
    const char *slash;
    size_t length;

    if (!text || !address)
        return -1;
    slash = strchr(text, '/');
    length = slash ? (size_t)(slash - text) : strlen(text);
    if (!length || length >= sizeof(buffer))
        return -1;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    return inet_pton(AF_INET, buffer, address) == 1 ? 0 : -1;
}

static int peer_reply_cb(struct nl_msg *message, void *user)
{
    struct failover_peer_list *result = user;
    struct nlmsghdr *nlh = nlmsg_hdr(message);
    struct nlattr *attrs[MWAN_ATTR_MAX + 1] = {0};
    struct nlattr *entry;
    int remaining;

    if (genlmsg_parse(nlh, 0, attrs, MWAN_ATTR_MAX, NULL) < 0 ||
        !attrs[MWAN_ATTR_NODE_ID] || !attrs[MWAN_ATTR_TUNNELS])
        return NL_SKIP;
    result->node_id = nla_get_u32(attrs[MWAN_ATTR_NODE_ID]);

    nla_for_each_nested(entry, attrs[MWAN_ATTR_TUNNELS], remaining) {
        struct nlattr *tun[MWAN_TUN_MAX + 1] = {0};
        struct failover_peer *peer;

        if (result->count >= MAX_SDWAN_TUNS ||
            nla_parse_nested(tun, MWAN_TUN_MAX, entry, NULL) < 0 ||
            !tun[MWAN_TUN_IFINDEX] || !tun[MWAN_TUN_STATE_SEQUENCE] ||
            !tun[MWAN_TUN_CONFIG_IFINDEX] ||
            !tun[MWAN_TUN_LOCAL_IPV4] || !tun[MWAN_TUN_IFNAME])
            continue;
        peer = &result->peers[result->count++];
        peer->ifindex = nla_get_u32(tun[MWAN_TUN_IFINDEX]);
        peer->configured_ifindex =
            nla_get_u32(tun[MWAN_TUN_CONFIG_IFINDEX]);
        snprintf(peer->ifname, sizeof(peer->ifname), "%s",
                 nla_get_string(tun[MWAN_TUN_IFNAME]));
        peer->local_ip.s_addr = nla_get_u32(tun[MWAN_TUN_LOCAL_IPV4]);
        peer->state_sequence = nla_get_u32(tun[MWAN_TUN_STATE_SEQUENCE]);
        if (tun[MWAN_TUN_PEER_IPV4] && tun[MWAN_TUN_PEER_GENERATION]) {
            peer->peer_ip.s_addr = nla_get_u32(tun[MWAN_TUN_PEER_IPV4]);
            peer->generation = nla_get_u32(tun[MWAN_TUN_PEER_GENERATION]);
            peer->resolved = peer->peer_ip.s_addr != 0;
        }
    }
    return NL_OK;
}

static int failover_get_peers(struct failover_peer_list *result)
{
    struct nl_sock *socket = NULL;
    struct nl_msg *message = NULL;
    int family;
    int ret = -1;

    memset(result, 0, sizeof(*result));
    socket = nl_socket_alloc();
    if (!socket || genl_connect(socket) < 0)
        goto out;
    family = genl_ctrl_resolve(socket, MWAN_GENL_NAME);
    if (family < 0)
        goto out;
    message = nlmsg_alloc();
    if (!message || !genlmsg_put(message, NL_AUTO_PORT, NL_AUTO_SEQ, family,
                                 0, 0, MWAN_CMD_GET_TUNNEL_PEERS,
                                 MWAN_GENL_VERSION))
        goto out;
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, peer_reply_cb,
                        result);
    ret = nl_send_auto(socket, message);
    if (ret >= 0)
        ret = nl_recvmsgs_default(socket);
out:
    if (message)
        nlmsg_free(message);
    if (socket)
        nl_socket_free(socket);
    return ret < 0 ? -1 : 0;
}

static int failover_set_kernel_state(unsigned int ifindex, bool up,
                                     uint32_t sequence)
{
    struct nl_sock *socket = NULL;
    struct nl_msg *message = NULL;
    int family;
    int ret = -1;

    socket = nl_socket_alloc();
    if (!socket || genl_connect(socket) < 0)
        goto out;
    family = genl_ctrl_resolve(socket, MWAN_GENL_NAME);
    if (family < 0)
        goto out;
    message = nlmsg_alloc();
    if (!message || !genlmsg_put(message, NL_AUTO_PORT, NL_AUTO_SEQ, family,
                                 0, 0, MWAN_CMD_SET_TUNNEL_STATE,
                                 MWAN_GENL_VERSION) ||
        nla_put_u32(message, MWAN_ATTR_TUNNEL_IFINDEX, ifindex) < 0 ||
        nla_put_u8(message, MWAN_ATTR_TUNNEL_UP, up ? 1 : 0) < 0 ||
        nla_put_u32(message, MWAN_ATTR_STATE_SEQUENCE, sequence) < 0)
        goto out;
    ret = nl_send_auto(socket, message);
    if (ret >= 0)
        ret = nl_wait_for_ack(socket);
out:
    if (message)
        nlmsg_free(message);
    if (socket)
        nl_socket_free(socket);
    return ret < 0 ? -1 : 0;
}

static void bfd_raw_changed(const struct bfd_session *session,
                            enum bfd_state old_state,
                            enum bfd_state new_state,
                            const char *reason, void *user)
{
    struct failover_runtime_entry *entry = user;

    log_info("[FAILOVER raw] tunnel=%s ifindex=%u %s->%s reason=%s detect=%uus",
             entry->ifname, entry->ifindex, bfd_state_name(old_state),
             bfd_state_name(new_state), reason,
             bfd_session_detection_time_us(session));
}

static void bfd_published_changed(const struct bfd_session *session,
                                  enum bfd_stable_state old_state,
                                  enum bfd_stable_state new_state, void *user)
{
    struct failover_runtime_entry *entry = user;
    bool up = new_state == BFD_STABLE_UP;
    uint32_t next_sequence = entry->state_sequence + 1U;

    (void)session;
    if (!next_sequence)
        next_sequence = 1;
    if (failover_set_kernel_state(entry->ifindex, up, next_sequence) == 0) {
        entry->state_sequence = next_sequence;
        log_info("[FAILOVER published] tunnel=%s ifindex=%u %s->%s seq=%u",
                 entry->ifname, entry->ifindex,
                 bfd_stable_state_name(old_state),
                 bfd_stable_state_name(new_state), next_sequence);
    } else {
        log_error("[FAILOVER] failed to publish %s for tunnel=%s ifindex=%u",
                  bfd_stable_state_name(new_state), entry->ifname,
                  entry->ifindex);
    }
}

static const struct failover_peer *find_peer(
    const struct failover_peer_list *peers, unsigned int ifindex)
{
    size_t i;

    for (i = 0; i < peers->count; i++)
        if (peers->peers[i].configured_ifindex == ifindex &&
            peers->peers[i].resolved)
            return &peers->peers[i];
    return NULL;
}

static const struct failover_peer *find_configured_tunnel(
    const struct failover_peer_list *peers, unsigned int ifindex)
{
    size_t i;

    for (i = 0; i < peers->count; i++)
        if (peers->peers[i].configured_ifindex == ifindex)
            return &peers->peers[i];
    return NULL;
}

static bool kernel_config_matches(const struct failover_snapshot *snapshot,
                                  const struct failover_peer_list *peers)
{
    size_t i;

    if ((uint32_t)snapshot->node_id != peers->node_id ||
        snapshot->count != peers->count)
        return false;
    for (i = 0; i < snapshot->count; i++) {
        const struct failover_peer *tunnel = find_configured_tunnel(
            peers, snapshot->tunnels[i].ifindex);

        if (!tunnel || tunnel->local_ip.s_addr !=
                       snapshot->tunnels[i].local_ip.s_addr)
            return false;
    }
    return true;
}

static bool runtime_matches(const struct failover_snapshot *snapshot,
                            const struct failover_peer_list *peers)
{
    size_t expected = 0;
    size_t i;

    for (i = 0; i < snapshot->count; i++)
        if (find_peer(peers, snapshot->tunnels[i].ifindex))
            expected++;
    if (expected != runtime_count)
        return false;
    for (i = 0; i < runtime_count; i++) {
        const struct failover_peer *peer = find_peer(peers,
                                                     runtime[i].configured_ifindex);
        if (!peer || peer->peer_ip.s_addr != runtime[i].peer_ip.s_addr ||
            peer->local_ip.s_addr != runtime[i].local_ip.s_addr ||
            peer->ifindex != runtime[i].ifindex ||
            strncmp(peer->ifname, runtime[i].ifname, IFNAMSIZ) != 0 ||
            peer->generation != runtime[i].peer_generation)
            return false;
    }
    return true;
}

static struct bfd_manager *rebuild_manager(
    struct bfd_manager *manager, const struct failover_snapshot *snapshot,
    const struct failover_peer_list *peers)
{
    const struct bfd_stability_config stability = {
        .up_hold_ms = 3000,
        .down_hold_ms = 0,
        .half_life_ms = 15000,
        .flap_penalty = 1000,
        .suppress_threshold = 2000,
        .reuse_threshold = 750,
    };
    size_t i;

    bfd_manager_destroy(manager);
    manager = NULL;
    runtime_count = 0;
    if (!snapshot->count)
        return NULL;
    manager = bfd_manager_create(NULL);
    if (!manager) {
        log_error("[FAILOVER] cannot create multi-tunnel BFD manager: %s",
                  strerror(errno));
        return NULL;
    }

    for (i = 0; i < snapshot->count; i++) {
        const struct failover_tunnel_config *configured =
            &snapshot->tunnels[i];
        const struct failover_peer *peer = find_peer(peers,
                                                     configured->ifindex);
        struct failover_runtime_entry *entry;
        struct bfd_session_config session_config;
        struct bfd_callbacks callbacks;
        uint32_t down_sequence;

        if (!peer)
            continue;
        entry = &runtime[runtime_count];
        memset(entry, 0, sizeof(*entry));
        entry->configured_ifindex = configured->ifindex;
        entry->ifindex = peer->ifindex;
        memcpy(entry->ifname, peer->ifname, sizeof(entry->ifname));
        entry->local_ip = peer->local_ip;
        entry->peer_ip = peer->peer_ip;
        entry->peer_generation = peer->generation;
        entry->state_sequence = peer->state_sequence;

        down_sequence = entry->state_sequence + 1U;
        if (!down_sequence)
            down_sequence = 1;
        if (failover_set_kernel_state(entry->ifindex, false,
                                      down_sequence) == 0)
            entry->state_sequence = down_sequence;

        memset(&session_config, 0, sizeof(session_config));
        session_config.ifname = entry->ifname;
        session_config.local_ip = entry->local_ip;
        session_config.peer_ip = entry->peer_ip;
        session_config.desired_min_tx_us = FAILOVER_BFD_INTERVAL_US;
        session_config.required_min_rx_us = FAILOVER_BFD_INTERVAL_US;
        session_config.detect_mult = FAILOVER_BFD_DETECT_MULT;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.raw_state_changed = bfd_raw_changed;
        callbacks.published_state_changed = bfd_published_changed;
        callbacks.user = entry;
        if (!bfd_manager_add_session(manager, &session_config, &stability,
                                     &callbacks)) {
            log_error("[FAILOVER] cannot create BFD session tunnel=%s: %s",
                      entry->ifname, strerror(errno));
            continue;
        }
        runtime_count++;
        {
            char local[INET_ADDRSTRLEN];
            char remote[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &entry->local_ip, local, sizeof(local));
            inet_ntop(AF_INET, &entry->peer_ip, remote, sizeof(remote));
            log_info("[FAILOVER] BFD session tunnel=%s ifindex=%u %s->%s",
                     entry->ifname, entry->ifindex, local, remote);
        }
    }
    return manager;
}

static void wait_without_manager(void)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += FAILOVER_RECONCILE_MS * 1000000UL;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&service.lock);
    if (!service.stop)
        pthread_cond_timedwait(&service.cond, &service.lock, &deadline);
    pthread_mutex_unlock(&service.lock);
}

static void *failover_worker(void *unused)
{
    struct bfd_manager *manager = NULL;
    struct failover_snapshot snapshot = {0};
    uint64_t applied_generation = 0;

    (void)unused;
    for (;;) {
        struct failover_peer_list peers;
        uint64_t desired_generation;
        bool stop;

        pthread_mutex_lock(&service.lock);
        stop = service.stop;
        desired_generation = service.desired_generation;
        if (desired_generation != applied_generation)
            snapshot = service.desired;
        pthread_mutex_unlock(&service.lock);
        if (stop)
            break;

        if (failover_get_peers(&peers) == 0) {
            if (!kernel_config_matches(&snapshot, &peers)) {
                bfd_manager_destroy(manager);
                manager = NULL;
                runtime_count = 0;
                applied_generation = UINT64_MAX;
            } else if (desired_generation != applied_generation ||
                       !runtime_matches(&snapshot, &peers)) {
                manager = rebuild_manager(manager, &snapshot, &peers);
                applied_generation = desired_generation;
            }
        }
        if (manager)
            (void)bfd_manager_poll(manager, FAILOVER_RECONCILE_MS);
        else
            wait_without_manager();
    }
    bfd_manager_destroy(manager);
    runtime_count = 0;
    return NULL;
}

static void failover_service_cleanup(void)
{
    pthread_t thread;
    bool join = false;

    pthread_mutex_lock(&service.lock);
    if (service.started) {
        service.stop = true;
        thread = service.thread;
        join = true;
        pthread_cond_broadcast(&service.cond);
    }
    pthread_mutex_unlock(&service.lock);
    if (join)
        pthread_join(thread, NULL);
    pthread_mutex_lock(&service.lock);
    service.started = false;
    pthread_mutex_unlock(&service.lock);
}

int failover_service_reconcile(const app_context_t *ctx)
{
    struct failover_snapshot next = {0};
    size_t i;

    if (!ctx)
        return -1;
    next.node_id = ctx->cfg.node_id;
    for (i = 0; i < ctx->cfg.sdwan_tun_count &&
                next.count < MAX_SDWAN_TUNS; i++) {
        const sdwan_tun_cfg_t *source = &ctx->cfg.sdwan_tuns[i];
        struct failover_tunnel_config *target =
            &next.tunnels[next.count];

        target->ifindex = if_nametoindex(source->tunnel_ifname);
        if (!target->ifindex ||
            parse_local_ipv4(source->tunnel_ip, &target->local_ip) < 0) {
            log_warn("[FAILOVER] skip invalid tunnel=%s local_ip=%s",
                     source->tunnel_ifname, source->tunnel_ip);
            memset(target, 0, sizeof(*target));
            continue;
        }
        memcpy(target->ifname, source->tunnel_ifname,
               sizeof(target->ifname));
        next.count++;
    }

    pthread_mutex_lock(&service.lock);
    if (memcmp(&next, &service.desired, sizeof(next)) != 0) {
        service.desired = next;
        service.desired_generation++;
        pthread_cond_broadcast(&service.cond);
    }
    if (!service.cleanup_registered) {
        if (atexit(failover_service_cleanup) == 0)
            service.cleanup_registered = true;
    }
    if (!service.started) {
        service.stop = false;
        if (pthread_create(&service.thread, NULL, failover_worker, NULL) != 0) {
            pthread_mutex_unlock(&service.lock);
            log_error("[FAILOVER] cannot start worker thread");
            return -1;
        }
        service.started = true;
        log_info("[FAILOVER] service started");
    }
    pthread_mutex_unlock(&service.lock);
    return 0;
}
