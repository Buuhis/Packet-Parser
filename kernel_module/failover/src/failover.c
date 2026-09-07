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

struct failover_desired_tunnel {
    char ifname[IFNAMSIZ];
    struct in_addr local_ip;
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
    unsigned int ifindex;
    struct in_addr local_ip;
    struct in_addr peer_ip;
    struct bfd_session *session;
    enum bfd_stable_state published;
    enum bfd_stable_state kernel_published;
    uint32_t config_generation;
    uint32_t state_sequence;
    bool state_dirty;
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

static bool runtime_matches(const struct failover_runtime_entry *entry,
                            unsigned int ifindex,
                            const struct in_addr *local_ip,
                            const struct in_addr *peer_ip)
{
    return entry && entry->in_use && entry->ifindex == ifindex &&
           entry->local_ip.s_addr == local_ip->s_addr &&
           entry->peer_ip.s_addr == peer_ip->s_addr;
}

static void remove_stale_entries(
    struct bfd_manager *manager,
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
    const struct failover_snapshot *snapshot)
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        const struct failover_desired_tunnel *desired;
        unsigned int current_ifindex;

        if (!entries[i].in_use)
            continue;
        desired = find_desired(snapshot, entries[i].ifname);
        current_ifindex = if_nametoindex(entries[i].ifname);
        if (!desired) {
            remove_runtime_entry(manager, &entries[i], "NOT_DESIRED");
        } else if (current_ifindex == 0) {
            remove_runtime_entry(manager, &entries[i], "INTERFACE_MISSING");
        } else if (current_ifindex != entries[i].ifindex) {
            remove_runtime_entry(manager, &entries[i], "IFINDEX_CHANGED");
        } else if (desired->local_ip.s_addr != entries[i].local_ip.s_addr) {
            remove_runtime_entry(manager, &entries[i], "LOCAL_IP_CHANGED");
        }
    }
}

static void reconcile_sessions(
    struct bfd_manager *manager,
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS],
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

    remove_stale_entries(manager, entries, snapshot);
    for (i = 0; i < snapshot->count; i++) {
        const struct failover_desired_tunnel *desired =
            &snapshot->tunnels[i];
        struct failover_runtime_entry *entry;
        struct bfd_session_config config;
        struct bfd_callbacks callbacks;
        struct in_addr peer_ip;
        char peer_text[INET_ADDRSTRLEN];
        unsigned int ifindex;

        ifindex = if_nametoindex(desired->ifname);
        if (ifindex == 0 ||
            !interface_has_ipv4(desired->ifname, &desired->local_ip))
            continue;
        entry = find_runtime(entries, desired->ifname);
        if (entry && entry->ifindex == ifindex &&
            entry->local_ip.s_addr == desired->local_ip.s_addr) {
            if (entry->config_generation != snapshot->config_generation) {
                uint32_t old_generation = entry->config_generation;
                char local[INET_ADDRSTRLEN];
                char peer[INET_ADDRSTRLEN];
                char kernel_peer[INET_ADDRSTRLEN] = "unavailable";
                struct in_addr current_peer_ip;
                const char *peer_match = "unknown";

                if (kernel_sync_get_tunnel_peer(
                        desired->ifname, kernel_peer,
                        sizeof(kernel_peer)) == 0 &&
                    inet_pton(AF_INET, kernel_peer, &current_peer_ip) == 1) {
                    peer_match = current_peer_ip.s_addr == entry->peer_ip.s_addr
                        ? "yes" : "no";
                }

                entry->config_generation = snapshot->config_generation;
                entry->state_sequence = 1;
                entry->state_dirty = true;
                log_info("[BFD-DIAG] event=session_reuse tunnel=%s "
                         "ifindex=%u local=%s stored_peer=%s kernel_peer=%s "
                         "peer_match=%s old_generation=%" PRIu32
                         " new_generation=%" PRIu32 " raw=%s published=%s",
                         entry->ifname, entry->ifindex,
                         format_ipv4(&entry->local_ip, local),
                         format_ipv4(&entry->peer_ip, peer), kernel_peer,
                         peer_match, old_generation, entry->config_generation,
                         entry->session
                             ? bfd_state_name(
                                   bfd_session_raw_state(entry->session))
                             : "NO_SESSION",
                         bfd_stable_state_name(entry->published));
            }
            continue;
        }
        if (kernel_sync_get_tunnel_peer(desired->ifname, peer_text,
                                        sizeof(peer_text)) != 0 ||
            inet_pton(AF_INET, peer_text, &peer_ip) != 1)
            continue;

        if (runtime_matches(entry, ifindex, &desired->local_ip, &peer_ip))
            continue;
        if (entry)
            remove_runtime_entry(manager, entry, "IDENTITY_CHANGED");
        entry = find_free_runtime(entries);
        if (!entry)
            continue;

        memset(entry, 0, sizeof(*entry));
        entry->in_use = true;
        entry->ifindex = ifindex;
        entry->local_ip = desired->local_ip;
        entry->peer_ip = peer_ip;
        entry->published = BFD_STABLE_DOWN;
        entry->kernel_published = BFD_STABLE_DOWN;
        entry->config_generation = snapshot->config_generation;
        entry->state_sequence = 1;
        entry->state_dirty = true;
        snprintf(entry->ifname, sizeof(entry->ifname), "%s",
                 desired->ifname);

        memset(&config, 0, sizeof(config));
        config.ifname = entry->ifname;
        config.local_ip = entry->local_ip;
        config.peer_ip = entry->peer_ip;
        config.desired_min_tx_us = FAILOVER_BFD_INTERVAL_US;
        config.required_min_rx_us = FAILOVER_BFD_INTERVAL_US;
        config.detect_mult = FAILOVER_BFD_DETECT_MULT;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.raw_state_changed = raw_state_changed;
        callbacks.published_state_changed = published_state_changed;
        callbacks.user = entry;
        entry->session = bfd_manager_add_session(manager, &config,
                                                 &stability, &callbacks);
        if (!entry->session) {
            char local[INET_ADDRSTRLEN];
            char peer[INET_ADDRSTRLEN];

            log_warn("[BFD-DIAG] event=session_create_failed tunnel=%s "
                     "ifindex=%u local=%s peer=%s generation=%" PRIu32,
                     entry->ifname, entry->ifindex,
                     format_ipv4(&entry->local_ip, local),
                     format_ipv4(&entry->peer_ip, peer),
                     entry->config_generation);
            memset(entry, 0, sizeof(*entry));
        } else {
            char local[INET_ADDRSTRLEN];
            char peer[INET_ADDRSTRLEN];

            log_info("[BFD-DIAG] event=session_create tunnel=%s ifindex=%u "
                     "local=%s peer=%s generation=%" PRIu32,
                     entry->ifname, entry->ifindex,
                     format_ipv4(&entry->local_ip, local),
                     format_ipv4(&entry->peer_ip, peer),
                     entry->config_generation);
        }
    }
}

static void flush_published_states(
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS])
{
    size_t i;

    for (i = 0; i < MAX_SDWAN_TUNS; i++) {
        struct failover_runtime_entry *entry = &entries[i];

        if (!entry->in_use || !entry->session || !entry->state_dirty ||
            entry->config_generation == 0 || entry->state_sequence == 0)
            continue;
        if (kernel_sync_set_tunnel_state(
                entry->ifname, entry->config_generation,
                entry->state_sequence,
                entry->published == BFD_STABLE_UP) == 0) {
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
            entry->state_dirty = false;
        }
    }
}

static void *failover_worker(void *unused)
{
    struct failover_runtime_entry entries[MAX_SDWAN_TUNS] = {{0}};
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

        reconcile_sessions(manager, entries, &snapshot);
        flush_published_states(entries);
        applied_generation = desired_generation;
        (void)bfd_manager_poll(manager, FAILOVER_RECONCILE_MS);
        flush_published_states(entries);
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
