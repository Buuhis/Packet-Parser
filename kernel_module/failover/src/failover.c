#define _GNU_SOURCE
#include "failover.h"
#include "kernel_sync.h"
#include "utils/logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define FAILOVER_RECONCILE_MS       250
#define FAILOVER_BFD_INTERVAL_US    300000U
#define FAILOVER_BFD_DETECT_MULT    3U
#define FAILOVER_BFD_UP_HOLD_MS     5000U
#define FAILOVER_DIAG_REPEAT_MS     5000U

enum failover_wait_stage {
    FAILOVER_WAIT_NONE = 0,
    FAILOVER_WAIT_INTERFACE,
    FAILOVER_WAIT_LOCAL_IP,
    FAILOVER_WAIT_RUNTIME_SLOT,
    FAILOVER_WAIT_KERNEL_STATE,
    FAILOVER_WAIT_DOWN_ACK,
    FAILOVER_WAIT_REBIND,
    FAILOVER_WAIT_PEER,
    FAILOVER_WAIT_SESSION_CREATE,
    FAILOVER_WAIT_STATE_PUBLISH,
};

struct failover_wait_diag {
    bool in_use;
    char ifname[IFNAMSIZ];
    enum failover_wait_stage stage;
    int error;
    uint32_t observed_generation;
    uint64_t last_log_ms;
};

struct failover_desired_tunnel {
    char ifname[IFNAMSIZ];
    char physical_ifname[IFNAMSIZ];
    struct in_addr local_ip;
    int segment_id;
};

struct failover_snapshot {
    int node_id;
    uint32_t config_generation;
    size_t count;
    struct failover_desired_tunnel tunnels[MAX_SDWAN_TUNS];
};

struct failover_runtime_entry {
    bool in_use;
    char ifname[IFNAMSIZ];
    char physical_ifname[IFNAMSIZ];
    unsigned int ifindex;
    struct in_addr local_ip;
    struct in_addr peer_ip;
    int segment_id;
    struct bfd_session *session;
    enum bfd_stable_state published;
    enum bfd_stable_state kernel_published;
    uint32_t config_generation;
    uint32_t state_sequence;
    bool state_dirty;
    bool rebind_pending;
};

struct failover_service {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t thread;
    bool started;
    bool stop;
    uint64_t desired_generation;
    struct failover_snapshot desired;
};

static struct failover_service service = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static int parse_ipv4_cidr(const char *text, struct in_addr *address)
{
    char buffer[INET_ADDRSTRLEN];
    const char *slash;
    size_t length;

    if (!text || !text[0] || !address)
        return -EINVAL;
    slash = strchr(text, '/');
    length = slash ? (size_t)(slash - text) : strlen(text);
    if (length == 0 || length >= sizeof(buffer))
        return -EINVAL;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    return inet_pton(AF_INET, buffer, address) == 1 ? 0 : -EINVAL;
}

static bool interface_has_ipv4(const char *ifname,
                               const struct in_addr *address)
{
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *current;
    bool found = false;

    if (getifaddrs(&interfaces) < 0)
        return false;
    for (current = interfaces; current; current = current->ifa_next) {
        const struct sockaddr_in *ipv4;

        if (!current->ifa_addr || current->ifa_addr->sa_family != AF_INET ||
            strcmp(current->ifa_name, ifname) != 0)
            continue;
        ipv4 = (const struct sockaddr_in *)current->ifa_addr;
        if (ipv4->sin_addr.s_addr == address->s_addr) {
            found = true;
            break;
        }
    }
    freeifaddrs(interfaces);
    return found;
}

static const struct failover_desired_tunnel *find_desired(
    const struct failover_snapshot *snapshot, const char *ifname)
{
    size_t i;

    for (i = 0; i < snapshot->count; i++) {
        if (strncmp(snapshot->tunnels[i].ifname, ifname, IFNAMSIZ) == 0)
            return &snapshot->tunnels[i];
    }
    return NULL;
}

static struct failover_runtime_entry *find_runtime(
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
    const char *ifname)
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        if (entries[i].in_use &&
            strncmp(entries[i].ifname, ifname, IFNAMSIZ) == 0)
            return &entries[i];
    }
    return NULL;
}

static struct failover_runtime_entry *find_free_runtime(
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS])
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        if (!entries[i].in_use)
            return &entries[i];
    }
    return NULL;
}

static const char *format_ipv4(const struct in_addr *address,
                               char buffer[INET_ADDRSTRLEN])
{
    return address && inet_ntop(AF_INET, address, buffer, INET_ADDRSTRLEN)
        ? buffer : "unknown";
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000U +
           (uint64_t)now.tv_nsec / 1000000U;
}

static const char *wait_stage_name(enum failover_wait_stage stage)
{
    switch (stage) {
    case FAILOVER_WAIT_INTERFACE: return "WAIT_INTERFACE";
    case FAILOVER_WAIT_LOCAL_IP: return "WAIT_LOCAL_IP";
    case FAILOVER_WAIT_RUNTIME_SLOT: return "WAIT_RUNTIME_SLOT";
    case FAILOVER_WAIT_KERNEL_STATE: return "WAIT_KERNEL_STATE";
    case FAILOVER_WAIT_DOWN_ACK: return "WAIT_DOWN_ACK";
    case FAILOVER_WAIT_REBIND: return "WAIT_REBIND";
    case FAILOVER_WAIT_PEER: return "WAIT_PEER_DISCOVERY";
    case FAILOVER_WAIT_SESSION_CREATE: return "WAIT_SESSION_CREATE";
    case FAILOVER_WAIT_STATE_PUBLISH: return "WAIT_STATE_PUBLISH";
    default: return "READY";
    }
}

static struct failover_wait_diag *find_wait_diag(
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS],
    const char *ifname)
{
    struct failover_wait_diag *free_entry = NULL;
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        if (diagnostics[i].in_use &&
            strncmp(diagnostics[i].ifname, ifname, IFNAMSIZ) == 0)
            return &diagnostics[i];
        if (!diagnostics[i].in_use && !free_entry)
            free_entry = &diagnostics[i];
    }
    if (free_entry) {
        memset(free_entry, 0, sizeof(*free_entry));
        free_entry->in_use = true;
        snprintf(free_entry->ifname, sizeof(free_entry->ifname), "%s",
                 ifname);
    }
    return free_entry;
}

static void report_wait_stage(
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS],
    const char *ifname, enum failover_wait_stage stage, int error,
    unsigned int ifindex, const struct in_addr *local_ip,
    uint32_t expected_generation, uint32_t observed_generation)
{
    struct failover_wait_diag *diag;
    char local[INET_ADDRSTRLEN];
    uint64_t now = monotonic_ms();

    diag = find_wait_diag(diagnostics, ifname);
    if (!diag)
        return;
    if (diag->stage == stage && diag->error == error &&
        diag->observed_generation == observed_generation &&
        now >= diag->last_log_ms &&
        now - diag->last_log_ms < FAILOVER_DIAG_REPEAT_MS)
        return;

    diag->stage = stage;
    diag->error = error;
    diag->observed_generation = observed_generation;
    diag->last_log_ms = now;
    log_warn("[BFD-RECONCILE] tunnel=%s stage=%s ifindex=%u local=%s "
             "expected_generation=%" PRIu32 " observed_generation=%" PRIu32
             " error=%d(%s) retry=1",
             ifname, wait_stage_name(stage), ifindex,
             format_ipv4(local_ip, local), expected_generation,
             observed_generation, error,
             error < 0 ? strerror(-error) : "none");
}

static void clear_wait_stage(
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS],
    const char *ifname)
{
    struct failover_wait_diag *diag = find_wait_diag(diagnostics, ifname);

    if (diag)
        memset(diag, 0, sizeof(*diag));
}

static void raw_state_changed(const struct bfd_session *session,
                              enum bfd_state old_state,
                              enum bfd_state new_state,
                              const char *reason,
                              void *user)
{
    const struct bfd_counters *counters = bfd_session_counters(session);
    struct failover_runtime_entry *entry = user;
    char local[INET_ADDRSTRLEN];
    char peer[INET_ADDRSTRLEN];

    if (!entry || !session || old_state == new_state)
        return;
    log_info("[BFD-DIAG] event=raw_state tunnel=%s ifindex=%u local=%s "
             "peer=%s generation=%" PRIu32 " old=%s new=%s reason=%s "
             "detect_us=%" PRIu32 " tx=%" PRIu64 " rx=%" PRIu64
             " path_drops=%" PRIu64 " peer_drops=%" PRIu64
             " discriminator_drops=%" PRIu64 " timeouts=%" PRIu64,
             entry->ifname, entry->ifindex,
             format_ipv4(bfd_session_local_ip(session), local),
             format_ipv4(bfd_session_peer_ip(session), peer),
             entry->config_generation, bfd_state_name(old_state),
             bfd_state_name(new_state), reason ? reason : "unknown",
             bfd_session_detection_time_us(session),
             counters ? counters->tx_packets : 0,
             counters ? counters->rx_packets : 0,
             counters ? counters->path_drops : 0,
             counters ? counters->peer_drops : 0,
             counters ? counters->discriminator_drops : 0,
             counters ? counters->timeouts : 0);
}

static void published_state_changed(const struct bfd_session *session,
                                    enum bfd_stable_state old_state,
                                    enum bfd_stable_state new_state,
                                    void *user)
{
    struct failover_runtime_entry *entry = user;
    (void)session;
    if (!entry || old_state == new_state)
        return;
    entry->published = new_state;
    entry->state_sequence++;
    if (entry->state_sequence == 0)
        entry->state_sequence = 1;
    entry->state_dirty = true;
}

static void remove_runtime_entry(struct bfd_manager *manager,
                                 struct failover_runtime_entry *entry,
                                 const char *reason)
{
    char local[INET_ADDRSTRLEN];
    char peer[INET_ADDRSTRLEN];

    if (!entry || !entry->in_use)
        return;
    log_info("[BFD-DIAG] event=session_remove tunnel=%s ifindex=%u "
             "local=%s peer=%s generation=%" PRIu32 " raw=%s "
             "published=%s reason=%s",
             entry->ifname, entry->ifindex,
             format_ipv4(&entry->local_ip, local),
             format_ipv4(&entry->peer_ip, peer), entry->config_generation,
             entry->session
                 ? bfd_state_name(bfd_session_raw_state(entry->session))
                 : "NO_SESSION",
             bfd_stable_state_name(entry->published),
             reason ? reason : "unknown");
    if (entry->session)
        (void)bfd_manager_remove_session(manager, entry->session);
    memset(entry, 0, sizeof(*entry));
}

static void stop_runtime_session(struct bfd_manager *manager,
                                 struct failover_runtime_entry *entry,
                                 const char *reason)
{
    char local[INET_ADDRSTRLEN];
    char peer[INET_ADDRSTRLEN];

    if (!entry || !entry->in_use || !entry->session)
        return;
    log_info("[BFD-DIAG] event=session_pause tunnel=%s ifindex=%u "
             "local=%s peer=%s generation=%" PRIu32 " reason=%s",
             entry->ifname, entry->ifindex,
             format_ipv4(&entry->local_ip, local),
             format_ipv4(&entry->peer_ip, peer), entry->config_generation,
             reason ? reason : "unknown");
    (void)bfd_manager_remove_session(manager, entry->session);
    entry->session = NULL;
}

static bool desired_identity_matches(
    const struct failover_runtime_entry *entry,
    const struct failover_desired_tunnel *desired)
{
    return entry->local_ip.s_addr == desired->local_ip.s_addr &&
           entry->segment_id == desired->segment_id &&
           strncmp(entry->physical_ifname, desired->physical_ifname,
                   IFNAMSIZ) == 0;
}

/* Force one tunnel out of active_paths before its device identity is
 * changed.  Sequence is read from the kernel first, so a daemon-side BFD
 * session restart can never regress the monotonic state sequence. */
static int publish_runtime_down(struct failover_runtime_entry *entry)
{
    struct kernel_tunnel_state state;
    uint32_t sequence;
    int ret;

    ret = kernel_sync_get_tunnel_state_by_ifindex(entry->ifindex, &state);
    if (ret)
        return ret;
    if (state.generation != entry->config_generation)
        return -ESTALE;

    entry->state_sequence = state.sequence;
    entry->kernel_published = state.up ? BFD_STABLE_UP : BFD_STABLE_DOWN;
    entry->published = BFD_STABLE_DOWN;
    entry->state_dirty = false;
    if (!state.up)
        return 0;
    if (state.sequence == UINT32_MAX)
        return -EOVERFLOW;
    sequence = state.sequence + 1;
    ret = kernel_sync_set_tunnel_state_by_ifindex(
        entry->ifindex, state.generation, sequence, false);
    if (ret)
        return ret;

    entry->state_sequence = sequence;
    entry->kernel_published = BFD_STABLE_DOWN;
    log_info("[BFD-STATE] tunnel=%s ifindex=%u UP->DOWN reason=CONFIG_REBIND",
             entry->ifname, entry->ifindex);
    return 0;
}

static void update_runtime_identity(
    struct failover_runtime_entry *entry,
    const struct failover_desired_tunnel *desired)
{
    entry->local_ip = desired->local_ip;
    entry->segment_id = desired->segment_id;
    snprintf(entry->physical_ifname, sizeof(entry->physical_ifname), "%s",
             desired->physical_ifname);
}

static int create_runtime_session(
    struct bfd_manager *manager, struct failover_runtime_entry *entry,
    const struct bfd_stability_config *stability)
{
    struct bfd_session_config config = {0};
    struct bfd_callbacks callbacks = {0};
    char local[INET_ADDRSTRLEN];
    char peer[INET_ADDRSTRLEN];

    config.ifname = entry->ifname;
    config.local_ip = entry->local_ip;
    config.peer_ip = entry->peer_ip;
    config.desired_min_tx_us = FAILOVER_BFD_INTERVAL_US;
    config.required_min_rx_us = FAILOVER_BFD_INTERVAL_US;
    config.detect_mult = FAILOVER_BFD_DETECT_MULT;
    callbacks.raw_state_changed = raw_state_changed;
    callbacks.published_state_changed = published_state_changed;
    callbacks.user = entry;
    entry->session = bfd_manager_add_session(manager, &config, stability,
                                             &callbacks);
    if (!entry->session) {
        log_warn("[BFD-DIAG] event=session_create_failed tunnel=%s "
                 "ifindex=%u local=%s peer=%s generation=%" PRIu32,
                 entry->ifname, entry->ifindex,
                 format_ipv4(&entry->local_ip, local),
                 format_ipv4(&entry->peer_ip, peer),
                 entry->config_generation);
        return -EIO;
    }
    log_info("[BFD-DIAG] event=session_create tunnel=%s ifindex=%u "
             "local=%s peer=%s generation=%" PRIu32,
             entry->ifname, entry->ifindex,
             format_ipv4(&entry->local_ip, local),
             format_ipv4(&entry->peer_ip, peer),
             entry->config_generation);
    return 0;
}

static void remove_undesired_entries(
    struct bfd_manager *manager,
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
    const struct failover_snapshot *snapshot)
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        const struct failover_desired_tunnel *desired;

        if (!entries[i].in_use)
            continue;
        desired = find_desired(snapshot, entries[i].ifname);
        if (!desired)
            remove_runtime_entry(manager, &entries[i], "NOT_DESIRED");
    }
}

static void reconcile_sessions(
    struct bfd_manager *manager,
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS],
    const struct failover_snapshot *snapshot)
{
    const struct bfd_stability_config stability = {
        .up_hold_ms = FAILOVER_BFD_UP_HOLD_MS,
        .down_hold_ms = 0,
        .half_life_ms = 15000,
        .flap_penalty = 1000,
        .suppress_threshold = 2000,
        .reuse_threshold = 750,
    };
    size_t i;

    remove_undesired_entries(manager, entries, snapshot);
    for (i = 0; i < snapshot->count; i++) {
        const struct failover_desired_tunnel *desired =
            &snapshot->tunnels[i];
        struct failover_runtime_entry *entry;
        struct kernel_tunnel_state kernel_state;
        struct in_addr peer_ip;
        char peer_text[INET_ADDRSTRLEN];
        unsigned int ifindex;
        bool identity_changed;
        bool has_local_ip;
        int ret;

        ifindex = if_nametoindex(desired->ifname);
        has_local_ip = ifindex &&
            interface_has_ipv4(desired->ifname, &desired->local_ip);
        entry = find_runtime(entries, desired->ifname);
        if (entry && entry->config_generation !=
                     snapshot->config_generation) {
            uint32_t old_generation = entry->config_generation;

            /* A full-config push also happens for -d/-a. Reuse a healthy
             * tunnel's live BFD session when its identity did not change;
             * only its kernel sequence namespace changed. */
            ret = ifindex ? kernel_sync_get_tunnel_state_by_ifindex(
                                ifindex, &kernel_state) : -ENODEV;
            if (ret || kernel_state.generation !=
                       snapshot->config_generation ||
                entry->ifindex != ifindex) {
                remove_runtime_entry(manager, entry,
                                     "CONFIG_DEVICE_CHANGED");
                entry = NULL;
            } else {
                entry->config_generation = kernel_state.generation;
                entry->state_sequence = kernel_state.sequence;
                entry->kernel_published = kernel_state.up ?
                    BFD_STABLE_UP : BFD_STABLE_DOWN;
                entry->state_dirty =
                    (kernel_state.up !=
                     (entry->published == BFD_STABLE_UP));
                log_info("[BFD-DIAG] event=session_reuse tunnel=%s "
                         "ifindex=%u old_generation=%" PRIu32
                         " new_generation=%" PRIu32 " published=%s",
                         entry->ifname, entry->ifindex, old_generation,
                         entry->config_generation,
                         bfd_stable_state_name(entry->published));
            }
        }
        if (!entry) {
            if (!ifindex) {
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_INTERFACE, -ENODEV, 0,
                                  &desired->local_ip,
                                  snapshot->config_generation, 0);
                continue;
            }
            if (!has_local_ip) {
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_LOCAL_IP,
                                  -EADDRNOTAVAIL, ifindex,
                                  &desired->local_ip,
                                  snapshot->config_generation, 0);
                continue;
            }
            entry = find_free_runtime(entries);
            if (!entry) {
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_RUNTIME_SLOT, -ENOSPC,
                                  ifindex, &desired->local_ip,
                                  snapshot->config_generation, 0);
                continue;
            }
            memset(entry, 0, sizeof(*entry));
            entry->in_use = true;
            entry->ifindex = ifindex;
            entry->config_generation = snapshot->config_generation;
            entry->published = BFD_STABLE_DOWN;
            snprintf(entry->ifname, sizeof(entry->ifname), "%s",
                     desired->ifname);
            update_runtime_identity(entry, desired);
            ret = kernel_sync_get_tunnel_state_by_ifindex(ifindex,
                                                          &kernel_state);
            if (ret || kernel_state.generation !=
                       snapshot->config_generation) {
                report_wait_stage(
                    diagnostics, desired->ifname,
                    FAILOVER_WAIT_KERNEL_STATE,
                    ret ? ret : -ESTALE, ifindex, &desired->local_ip,
                    snapshot->config_generation,
                    ret ? 0 : kernel_state.generation);
                memset(entry, 0, sizeof(*entry));
                continue;
            }
            entry->state_sequence = kernel_state.sequence;
            entry->kernel_published = kernel_state.up ?
                BFD_STABLE_UP : BFD_STABLE_DOWN;
            entry->state_dirty = false;
            ret = kernel_state.up ? publish_runtime_down(entry) : 0;
            if (ret) {
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_DOWN_ACK, ret, ifindex,
                                  &desired->local_ip,
                                  snapshot->config_generation,
                                  kernel_state.generation);
                memset(entry, 0, sizeof(*entry));
                continue;
            }
        }

        identity_changed = !desired_identity_matches(entry, desired);
        if (identity_changed || !ifindex || ifindex != entry->ifindex ||
            !has_local_ip) {
            ret = publish_runtime_down(entry);
            if (ret) {
                log_warn("[BFD-DIAG] event=rebind_down_failed tunnel=%s "
                         "ifindex=%u error=%s",
                         entry->ifname, entry->ifindex, strerror(-ret));
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_DOWN_ACK, ret,
                                  entry->ifindex, &desired->local_ip,
                                  snapshot->config_generation, 0);
                continue;
            }
            stop_runtime_session(manager, entry,
                                 identity_changed ? "CONFIG_CHANGED" :
                                 (!ifindex ? "INTERFACE_MISSING" :
                                  "INTERFACE_IDENTITY_CHANGED"));
            update_runtime_identity(entry, desired);
            entry->rebind_pending = true;
        }

        if (!ifindex) {
            report_wait_stage(diagnostics, desired->ifname,
                              FAILOVER_WAIT_INTERFACE, -ENODEV, 0,
                              &desired->local_ip,
                              snapshot->config_generation, 0);
            continue;
        }
        if (!has_local_ip) {
            report_wait_stage(diagnostics, desired->ifname,
                              FAILOVER_WAIT_LOCAL_IP, -EADDRNOTAVAIL,
                              ifindex, &desired->local_ip,
                              snapshot->config_generation, 0);
            continue;
        }

        if (entry->rebind_pending) {
            unsigned int old_ifindex = entry->ifindex;

            ret = kernel_sync_rebind_tunnel(
                snapshot->node_id, snapshot->config_generation,
                old_ifindex, ifindex);
            if (ret) {
                struct kernel_tunnel_state old_state;

                /* Netlink delivery and the ACK are separate. If only the
                 * ACK was lost, the old identity is gone and the new one is
                 * already queryable; accept that completed transaction. */
                if (old_ifindex != ifindex &&
                    kernel_sync_get_tunnel_state_by_ifindex(
                        old_ifindex, &old_state) == -ENOENT &&
                    kernel_sync_get_tunnel_state_by_ifindex(
                        ifindex, &kernel_state) == 0 &&
                    kernel_state.generation == entry->config_generation &&
                    !kernel_state.up) {
                    log_info("[BFD-DIAG] event=rebind_ack_recovered "
                             "tunnel=%s old_ifindex=%u new_ifindex=%u",
                             entry->ifname, old_ifindex, ifindex);
                    ret = 0;
                }
            }
            if (ret) {
                log_warn("[BFD-DIAG] event=rebind_deferred tunnel=%s "
                         "old_ifindex=%u new_ifindex=%u error=%s",
                         entry->ifname, old_ifindex, ifindex,
                         strerror(-ret));
                report_wait_stage(diagnostics, desired->ifname,
                                  FAILOVER_WAIT_REBIND, ret, ifindex,
                                  &desired->local_ip,
                                  snapshot->config_generation, 0);
                continue;
            }
            entry->ifindex = ifindex;
            entry->peer_ip.s_addr = 0;
            entry->rebind_pending = false;
            ret = kernel_sync_get_tunnel_state_by_ifindex(
                entry->ifindex, &kernel_state);
            if (ret || kernel_state.generation !=
                       entry->config_generation) {
                report_wait_stage(
                    diagnostics, desired->ifname,
                    FAILOVER_WAIT_KERNEL_STATE,
                    ret ? ret : -ESTALE, entry->ifindex,
                    &desired->local_ip, entry->config_generation,
                    ret ? 0 : kernel_state.generation);
                entry->rebind_pending = true;
                continue;
            }
            entry->state_sequence = kernel_state.sequence;
            entry->kernel_published = kernel_state.up ?
                BFD_STABLE_UP : BFD_STABLE_DOWN;
            log_info("[BFD-DIAG] event=rebind_complete tunnel=%s "
                     "old_ifindex=%u new_ifindex=%u segment_id=%d",
                     entry->ifname, old_ifindex, entry->ifindex,
                     entry->segment_id);
        }

        if (entry->session) {
            clear_wait_stage(diagnostics, desired->ifname);
            continue;
        }
        ret = kernel_sync_get_tunnel_peer(desired->ifname, peer_text,
                                          sizeof(peer_text));
        if (ret) {
            report_wait_stage(diagnostics, desired->ifname,
                              FAILOVER_WAIT_PEER, ret, entry->ifindex,
                              &desired->local_ip,
                              entry->config_generation,
                              entry->config_generation);
            continue;
        }
        if (inet_pton(AF_INET, peer_text, &peer_ip) != 1) {
            report_wait_stage(diagnostics, desired->ifname,
                              FAILOVER_WAIT_PEER, -EPROTO,
                              entry->ifindex, &desired->local_ip,
                              entry->config_generation,
                              entry->config_generation);
            continue;
        }
        entry->peer_ip = peer_ip;
        ret = create_runtime_session(manager, entry, &stability);
        if (ret)
            report_wait_stage(diagnostics, desired->ifname,
                              FAILOVER_WAIT_SESSION_CREATE, ret,
                              entry->ifindex, &desired->local_ip,
                              entry->config_generation,
                              entry->config_generation);
        else
            clear_wait_stage(diagnostics, desired->ifname);
    }
}

static void flush_published_states(
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS])
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        struct failover_runtime_entry *entry = &entries[i];
        struct kernel_tunnel_state state;
        uint32_t sequence;
        bool target_up;
        int ret;

        if (!entry->in_use || !entry->session || !entry->state_dirty ||
            entry->config_generation == 0)
            continue;
        ret = kernel_sync_get_tunnel_state_by_ifindex(entry->ifindex,
                                                      &state);
        if (ret || state.generation != entry->config_generation) {
            report_wait_stage(
                diagnostics, entry->ifname,
                FAILOVER_WAIT_STATE_PUBLISH, ret ? ret : -ESTALE,
                entry->ifindex, &entry->local_ip,
                entry->config_generation, ret ? 0 : state.generation);
            continue;
        }
        target_up = entry->published == BFD_STABLE_UP;
        entry->state_sequence = state.sequence;
        entry->kernel_published = state.up ? BFD_STABLE_UP : BFD_STABLE_DOWN;
        if (state.up == target_up) {
            entry->state_dirty = false;
            continue;
        }
        if (state.sequence == UINT32_MAX) {
            report_wait_stage(diagnostics, entry->ifname,
                              FAILOVER_WAIT_STATE_PUBLISH, -EOVERFLOW,
                              entry->ifindex, &entry->local_ip,
                              entry->config_generation, state.generation);
            continue;
        }
        sequence = state.sequence + 1;
        ret = kernel_sync_set_tunnel_state_by_ifindex(
            entry->ifindex, entry->config_generation,
            sequence, target_up);
        if (ret == 0) {
            if (entry->kernel_published != entry->published) {
                char peer[INET_ADDRSTRLEN] = "unknown";

                (void)inet_ntop(AF_INET, &entry->peer_ip, peer,
                                sizeof(peer));
                log_info("[BFD-STATE] tunnel=%s peer=%s %s->%s",
                         entry->ifname, peer,
                         bfd_stable_state_name(entry->kernel_published),
                         bfd_stable_state_name(entry->published));
                entry->kernel_published = entry->published;
            }
            entry->state_sequence = sequence;
            entry->state_dirty = false;
            clear_wait_stage(diagnostics, entry->ifname);
        } else {
            report_wait_stage(diagnostics, entry->ifname,
                              FAILOVER_WAIT_STATE_PUBLISH, ret,
                              entry->ifindex, &entry->local_ip,
                              entry->config_generation, state.generation);
        }
    }
}

static void *failover_worker(void *unused)
{
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS] = {{0}};
    struct failover_wait_diag diagnostics[MAX_SDWAN_TUNS] = {{0}};
    struct failover_snapshot snapshot = {0};
    struct bfd_manager *manager;
    uint64_t applied_generation = 0;

    (void)unused;
    manager = NULL;
    while (!manager) {
        struct timespec retry = { .tv_sec = 1, .tv_nsec = 0 };
        bool stop;

        pthread_mutex_lock(&service.lock);
        stop = service.stop;
        pthread_mutex_unlock(&service.lock);
        if (stop)
            return NULL;
        manager = bfd_manager_create();
        if (!manager)
            nanosleep(&retry, NULL);
    }

    for (;;) {
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

        reconcile_sessions(manager, entries, diagnostics, &snapshot);
        flush_published_states(entries, diagnostics);
        applied_generation = desired_generation;
        (void)bfd_manager_poll(manager, FAILOVER_RECONCILE_MS);
        flush_published_states(entries, diagnostics);
    }

    for (size_t i = 0; i < MAX_SDWAN_TUNS; i++)
        remove_runtime_entry(manager, &entries[i], "SERVICE_STOP");
    bfd_manager_destroy(manager);
    return NULL;
}

int failover_service_reconcile(const app_context_t *ctx,
                               uint32_t config_generation)
{
    struct failover_snapshot next = {0};
    size_t i;

    if (!ctx || config_generation == 0)
        return -EINVAL;
    next.node_id = ctx->cfg.node_id;
    next.config_generation = config_generation;
    for (i = 0; i < ctx->cfg.sdwan_tun_count &&
                next.count < MAX_SDWAN_TUNS; i++) {
        const sdwan_tun_cfg_t *source = &ctx->cfg.sdwan_tuns[i];
        struct failover_desired_tunnel *target =
            &next.tunnels[next.count];

        if (!source->tunnel_ifname[0] ||
            strnlen(source->tunnel_ifname, IFNAMSIZ) >= IFNAMSIZ ||
            parse_ipv4_cidr(source->tunnel_ip, &target->local_ip) < 0)
            continue;
        snprintf(target->ifname, sizeof(target->ifname), "%s",
                 source->tunnel_ifname);
        snprintf(target->physical_ifname, sizeof(target->physical_ifname),
                 "%s", source->physical_ifname);
        target->segment_id = source->segment_id;
        next.count++;
    }

    pthread_mutex_lock(&service.lock);
    if (memcmp(&next, &service.desired, sizeof(next)) != 0) {
        service.desired = next;
        service.desired_generation++;
        if (service.desired_generation == 0)
            service.desired_generation++;
        pthread_cond_broadcast(&service.cond);
    }
    if (!service.started) {
        int create_ret;

        service.stop = false;
        create_ret = pthread_create(&service.thread, NULL, failover_worker,
                                    NULL);
        if (create_ret != 0) {
            pthread_mutex_unlock(&service.lock);
            return -create_ret;
        }
        service.started = true;
    }
    pthread_mutex_unlock(&service.lock);
    return 0;
}

void failover_service_stop(void)
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
    service.stop = false;
    memset(&service.desired, 0, sizeof(service.desired));
    service.desired_generation = 0;
    pthread_mutex_unlock(&service.lock);
}
