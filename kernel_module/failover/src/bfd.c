#include "bfd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BFD_MAX_SESSIONS       16U
#define BFD_STARTUP_TX_US       1000000U
#define BFD_MIN_INTERVAL_US     1000U
#define BFD_MAX_EVENTS          4
#define BFD_EPHEMERAL_PORT_MIN  49152U
#define BFD_EPHEMERAL_PORT_COUNT 16384U
#define BFD_BIND_ATTEMPTS       128U

#define BFD_FLAG_AUTH           0x04U
#define BFD_FLAG_MULTIPOINT     0x01U

struct bfd_stabilizer {
    struct bfd_stability_config config;
    enum bfd_stable_state published;
    enum bfd_stabilizer_state state;
    uint64_t deadline_ns;
    uint64_t penalty_last_ns;
    uint32_t penalty;
    bool suppressed;
};

struct bfd_session {
    struct bfd_manager *manager;
    char ifname[IFNAMSIZ];
    struct in_addr local_ip;
    struct in_addr peer_ip;
    unsigned int ifindex;
    int tx_fd;

    uint32_t local_discriminator;
    uint32_t remote_discriminator;
    enum bfd_state raw_state;
    enum bfd_state remote_state;
    uint8_t local_detect_mult;
    uint8_t remote_detect_mult;
    uint32_t desired_min_tx_us;
    uint32_t required_min_rx_us;
    uint32_t remote_desired_min_tx_us;
    uint32_t remote_required_min_rx_us;
    uint32_t detection_time_us;
    uint64_t last_rx_ns;
    uint64_t next_tx_ns;
    uint64_t detection_deadline_ns;
    uint32_t prng;

    struct bfd_stabilizer stabilizer;
    struct bfd_callbacks callbacks;
    struct bfd_counters counters;
};

struct bfd_manager {
    int rx_fd;
    int epoll_fd;
    struct in_addr listen_ip;
    struct bfd_session *sessions[BFD_MAX_SESSIONS];
    size_t session_count;
};

_Static_assert(sizeof(struct bfd_control_packet) == BFD_CONTROL_LEN,
               "BFD control packet must be 24 bytes");

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t ms_to_ns(uint32_t ms)
{
    return (uint64_t)ms * UINT64_C(1000000);
}

static uint64_t us_to_ns(uint32_t us)
{
    return (uint64_t)us * UINT64_C(1000);
}

static uint32_t nonzero_random_u32(void)
{
    uint32_t value = 0;
    ssize_t ret = getrandom(&value, sizeof(value), GRND_NONBLOCK);

    if (ret != (ssize_t)sizeof(value) || value == 0) {
        value = (uint32_t)monotonic_ns() ^ (uint32_t)getpid() ^ 0x9e3779b9U;
    }
    return value == 0 ? 1U : value;
}

static uint32_t session_random(struct bfd_session *session)
{
    session->prng = session->prng * 1664525U + 1013904223U;
    return session->prng;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int bind_session_source(struct bfd_session *session)
{
    struct sockaddr_in local;
    unsigned int attempt;

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr = session->local_ip;
    for (attempt = 0; attempt < BFD_BIND_ATTEMPTS; attempt++) {
        uint32_t port = BFD_EPHEMERAL_PORT_MIN +
                        session_random(session) % BFD_EPHEMERAL_PORT_COUNT;

        local.sin_port = htons((uint16_t)port);
        if (bind(session->tx_fd, (const struct sockaddr *)&local,
                 sizeof(local)) == 0)
            return 0;
        if (errno != EADDRINUSE)
            return -1;
    }
    errno = EADDRINUSE;
    return -1;
}

const char *bfd_state_name(enum bfd_state state)
{
    switch (state) {
    case BFD_STATE_ADMIN_DOWN: return "ADMIN_DOWN";
    case BFD_STATE_DOWN:       return "DOWN";
    case BFD_STATE_INIT:       return "INIT";
    case BFD_STATE_UP:         return "UP";
    default:                   return "INVALID";
    }
}

const char *bfd_stable_state_name(enum bfd_stable_state state)
{
    switch (state) {
    case BFD_STABLE_UNKNOWN: return "UNKNOWN";
    case BFD_STABLE_DOWN:    return "DOWN";
    case BFD_STABLE_UP:      return "UP";
    default:                 return "INVALID";
    }
}

const char *bfd_stabilizer_state_name(enum bfd_stabilizer_state state)
{
    switch (state) {
    case BFD_STABILIZER_IDLE:         return "IDLE";
    case BFD_STABILIZER_DOWN_PENDING: return "DOWN_PENDING";
    case BFD_STABILIZER_UP_PENDING:   return "UP_PENDING";
    case BFD_STABILIZER_SUPPRESSED:   return "SUPPRESSED";
    default:                          return "INVALID";
    }
}

static void stabilizer_decay(struct bfd_stabilizer *stabilizer, uint64_t now_ns)
{
    uint64_t half_life_ns;

    if (stabilizer->config.half_life_ms == 0 || stabilizer->penalty == 0)
        return;

    half_life_ns = ms_to_ns(stabilizer->config.half_life_ms);
    while (now_ns - stabilizer->penalty_last_ns >= half_life_ns) {
        stabilizer->penalty = (stabilizer->penalty + 1U) / 2U;
        stabilizer->penalty_last_ns += half_life_ns;
    }
}

static void stabilizer_publish(struct bfd_session *session,
                               enum bfd_stable_state new_state)
{
    struct bfd_stabilizer *stabilizer = &session->stabilizer;
    enum bfd_stable_state old_state = stabilizer->published;

    if (old_state == new_state)
        return;

    stabilizer->published = new_state;
    session->counters.published_state_transitions++;
    if (session->callbacks.published_state_changed) {
        session->callbacks.published_state_changed(session, old_state, new_state,
                                                   session->callbacks.user);
    }
}

static void stabilizer_add_flap(struct bfd_session *session, uint64_t now_ns)
{
    struct bfd_stabilizer *stabilizer = &session->stabilizer;
    uint64_t summed;

    if (stabilizer->config.suppress_threshold == 0 ||
        stabilizer->config.flap_penalty == 0)
        return;

    stabilizer_decay(stabilizer, now_ns);
    summed = (uint64_t)stabilizer->penalty + stabilizer->config.flap_penalty;
    stabilizer->penalty = summed > UINT32_MAX ? UINT32_MAX : (uint32_t)summed;
    stabilizer->penalty_last_ns = now_ns;

    if (stabilizer->penalty >= stabilizer->config.suppress_threshold)
        stabilizer->suppressed = true;
}

static void stabilizer_start_up_pending(struct bfd_session *session, uint64_t now_ns)
{
    struct bfd_stabilizer *stabilizer = &session->stabilizer;

    if (stabilizer->suppressed) {
        stabilizer->state = BFD_STABILIZER_SUPPRESSED;
        stabilizer->deadline_ns = 0;
        return;
    }

    if (stabilizer->config.up_hold_ms == 0) {
        stabilizer_publish(session, BFD_STABLE_UP);
        stabilizer->state = BFD_STABILIZER_IDLE;
        stabilizer->deadline_ns = 0;
        return;
    }

    stabilizer->state = BFD_STABILIZER_UP_PENDING;
    stabilizer->deadline_ns = now_ns + ms_to_ns(stabilizer->config.up_hold_ms);
}

static void stabilizer_on_raw_change(struct bfd_session *session,
                                     enum bfd_state old_state,
                                     enum bfd_state new_state,
                                     uint64_t now_ns)
{
    struct bfd_stabilizer *stabilizer = &session->stabilizer;

    stabilizer_decay(stabilizer, now_ns);
    if (old_state == BFD_STATE_UP && new_state == BFD_STATE_DOWN)
        stabilizer_add_flap(session, now_ns);

    stabilizer->deadline_ns = 0;
    if (new_state == BFD_STATE_UP) {
        if (stabilizer->published != BFD_STABLE_UP)
            stabilizer_start_up_pending(session, now_ns);
        else
            stabilizer->state = BFD_STABILIZER_IDLE;
        return;
    }

    if (new_state == BFD_STATE_DOWN && stabilizer->published == BFD_STABLE_UP) {
        if (stabilizer->config.down_hold_ms == 0) {
            stabilizer_publish(session, BFD_STABLE_DOWN);
            stabilizer->state = BFD_STABILIZER_IDLE;
        } else {
            stabilizer->state = BFD_STABILIZER_DOWN_PENDING;
            stabilizer->deadline_ns = now_ns + ms_to_ns(stabilizer->config.down_hold_ms);
        }
        return;
    }

    stabilizer->state = stabilizer->suppressed ? BFD_STABILIZER_SUPPRESSED
                                                : BFD_STABILIZER_IDLE;
}

static void stabilizer_tick(struct bfd_session *session, uint64_t now_ns)
{
    struct bfd_stabilizer *stabilizer = &session->stabilizer;

    stabilizer_decay(stabilizer, now_ns);
    if (stabilizer->suppressed &&
        stabilizer->penalty <= stabilizer->config.reuse_threshold) {
        stabilizer->suppressed = false;
        if (session->raw_state == BFD_STATE_UP &&
            stabilizer->published != BFD_STABLE_UP) {
            stabilizer_start_up_pending(session, now_ns);
        } else {
            stabilizer->state = BFD_STABILIZER_IDLE;
        }
    }

    if (stabilizer->deadline_ns == 0 || now_ns < stabilizer->deadline_ns)
        return;

    if (stabilizer->state == BFD_STABILIZER_UP_PENDING &&
        session->raw_state == BFD_STATE_UP && !stabilizer->suppressed) {
        stabilizer_publish(session, BFD_STABLE_UP);
    } else if (stabilizer->state == BFD_STABILIZER_DOWN_PENDING &&
               session->raw_state == BFD_STATE_DOWN) {
        stabilizer_publish(session, BFD_STABLE_DOWN);
    }

    stabilizer->state = stabilizer->suppressed ? BFD_STABILIZER_SUPPRESSED
                                                : BFD_STABILIZER_IDLE;
    stabilizer->deadline_ns = 0;
}

static void raw_state_transition(struct bfd_session *session,
                                 enum bfd_state new_state,
                                 const char *reason,
                                 uint64_t now_ns)
{
    enum bfd_state old_state = session->raw_state;

    if (old_state == new_state)
        return;

    session->raw_state = new_state;
    session->counters.raw_state_transitions++;
    if (new_state == BFD_STATE_DOWN) {
        session->remote_discriminator = 0;
        session->detection_deadline_ns = 0;
    }

    /* Send a state update promptly; normal pacing resumes after this packet. */
    session->next_tx_ns = now_ns;
    stabilizer_on_raw_change(session, old_state, new_state, now_ns);
    if (session->callbacks.raw_state_changed) {
        session->callbacks.raw_state_changed(session, old_state, new_state, reason,
                                             session->callbacks.user);
    }
}

static uint32_t session_advertised_tx_us(const struct bfd_session *session)
{
    if (session->raw_state == BFD_STATE_UP)
        return session->desired_min_tx_us;
    return session->desired_min_tx_us > BFD_STARTUP_TX_US
        ? session->desired_min_tx_us : BFD_STARTUP_TX_US;
}

static void session_schedule_next_tx(struct bfd_session *session, uint64_t now_ns)
{
    uint32_t interval_us = session_advertised_tx_us(session);
    uint32_t minimum_reduction_pct;
    uint32_t reduction_pct;

    if (session->remote_required_min_rx_us > interval_us)
        interval_us = session->remote_required_min_rx_us;

    /* RFC 5880 section 6.8.7: periodic Control packets are sent 0--25%
     * earlier than the negotiated interval. With DetectMult=1 the range is
     * 10--25%, preventing two peers from repeatedly transmitting together. */
    minimum_reduction_pct = session->local_detect_mult == 1 ? 10U : 0U;
    reduction_pct = minimum_reduction_pct +
        session_random(session) % (26U - minimum_reduction_pct);
    interval_us -= (uint32_t)(((uint64_t)interval_us * reduction_pct) / 100U);
    session->next_tx_ns = now_ns + us_to_ns(interval_us);
}

static int session_send(struct bfd_session *session, uint64_t now_ns)
{
    struct bfd_control_packet packet;
    struct sockaddr_in peer;
    ssize_t sent;

    memset(&packet, 0, sizeof(packet));
    packet.version_diag = (uint8_t)(1U << 5U);
    packet.state_flags = (uint8_t)((uint8_t)session->raw_state << 6U);
    packet.detect_mult = session->local_detect_mult;
    packet.length = BFD_CONTROL_LEN;
    packet.my_discriminator = htonl(session->local_discriminator);
    packet.your_discriminator = htonl(session->remote_discriminator);
    packet.desired_min_tx = htonl(session_advertised_tx_us(session));
    packet.required_min_rx = htonl(session->required_min_rx_us);
    packet.required_min_echo_rx = 0;

    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(BFD_CONTROL_PORT);
    peer.sin_addr = session->peer_ip;
    sent = sendto(session->tx_fd, &packet, sizeof(packet), 0,
                  (const struct sockaddr *)&peer, sizeof(peer));
    session_schedule_next_tx(session, now_ns);
    if (sent != (ssize_t)sizeof(packet))
        return -1;

    session->counters.tx_packets++;
    return 0;
}

static bool packet_is_valid(const struct bfd_control_packet *packet, size_t length)
{
    uint8_t version;
    uint8_t state;

    if (length != sizeof(*packet) || packet->length != BFD_CONTROL_LEN)
        return false;
    version = packet->version_diag >> 5U;
    state = (packet->state_flags >> 6U) & 0x03U;
    if (version != 1U || packet->detect_mult == 0 || state > BFD_STATE_UP)
        return false;
    if ((packet->state_flags & (BFD_FLAG_AUTH | BFD_FLAG_MULTIPOINT)) != 0)
        return false;
    return ntohl(packet->my_discriminator) != 0;
}

static struct bfd_session *find_session(struct bfd_manager *manager,
                                        uint32_t your_discriminator,
                                        const struct in_addr *source,
                                        const struct in_addr *destination,
                                        unsigned int ifindex)
{
    size_t i;

    for (i = 0; i < manager->session_count; i++) {
        struct bfd_session *session = manager->sessions[i];

        if (session->local_ip.s_addr != destination->s_addr ||
            (session->ifindex != 0 && session->ifindex != ifindex))
            continue;

        if (your_discriminator != 0) {
            if (session->local_discriminator == your_discriminator)
                return session;
        } else if (session->peer_ip.s_addr == source->s_addr) {
            return session;
        }
    }
    return NULL;
}

static struct bfd_session *find_session_by_peer(struct bfd_manager *manager,
                                                const struct in_addr *source,
                                                const struct in_addr *destination,
                                                unsigned int ifindex)
{
    size_t i;

    for (i = 0; i < manager->session_count; i++) {
        if (manager->sessions[i]->peer_ip.s_addr == source->s_addr &&
            manager->sessions[i]->local_ip.s_addr == destination->s_addr &&
            (manager->sessions[i]->ifindex == 0 ||
             manager->sessions[i]->ifindex == ifindex))
            return manager->sessions[i];
    }
    return NULL;
}

static void update_detection_timer(struct bfd_session *session, uint64_t now_ns)
{
    uint32_t base_us;
    uint64_t detection_us;

    if (session->remote_detect_mult == 0 || session->remote_desired_min_tx_us == 0)
        return;

    base_us = session->required_min_rx_us > session->remote_desired_min_tx_us
        ? session->required_min_rx_us : session->remote_desired_min_tx_us;
    detection_us = (uint64_t)session->remote_detect_mult * base_us;
    if (detection_us > UINT32_MAX)
        detection_us = UINT32_MAX;
    session->detection_time_us = (uint32_t)detection_us;
    session->detection_deadline_ns = now_ns + us_to_ns(session->detection_time_us);
}

static void process_packet(struct bfd_manager *manager,
                           const struct bfd_control_packet *packet,
                           size_t length,
                           const struct sockaddr_in *source,
                           const struct in_addr *destination,
                           unsigned int ifindex,
                           int ttl,
                           uint64_t now_ns)
{
    uint32_t your_discriminator;
    uint32_t remote_discriminator;
    enum bfd_state remote_state;
    struct bfd_session *session;

    if (!packet_is_valid(packet, length)) {
        session = find_session_by_peer(manager, &source->sin_addr,
                                       destination, ifindex);
        if (session)
            session->counters.invalid_packets++;
        return;
    }
    your_discriminator = ntohl(packet->your_discriminator);
    remote_discriminator = ntohl(packet->my_discriminator);
    remote_state = (enum bfd_state)((packet->state_flags >> 6U) & 0x03U);
    session = find_session(manager, your_discriminator, &source->sin_addr,
                           destination, ifindex);
    if (!session)
        return;
    if (ttl != 255) {
        session->counters.ttl_drops++;
        return;
    }
    if (source->sin_addr.s_addr != session->peer_ip.s_addr) {
        session->counters.peer_drops++;
        return;
    }
    if (your_discriminator != 0 && your_discriminator != session->local_discriminator) {
        session->counters.discriminator_drops++;
        return;
    }
    if (your_discriminator == 0 && remote_state != BFD_STATE_DOWN &&
        remote_state != BFD_STATE_ADMIN_DOWN) {
        session->counters.discriminator_drops++;
        return;
    }

    session->counters.rx_packets++;
    session->last_rx_ns = now_ns;
    session->remote_discriminator = remote_discriminator;
    session->remote_state = remote_state;
    session->remote_detect_mult = packet->detect_mult;
    session->remote_desired_min_tx_us = ntohl(packet->desired_min_tx);
    session->remote_required_min_rx_us = ntohl(packet->required_min_rx);
    update_detection_timer(session, now_ns);

    switch (session->raw_state) {
    case BFD_STATE_DOWN:
        if (remote_state == BFD_STATE_DOWN)
            raw_state_transition(session, BFD_STATE_INIT, "REMOTE_DOWN", now_ns);
        else if (remote_state == BFD_STATE_INIT)
            raw_state_transition(session, BFD_STATE_UP, "REMOTE_INIT", now_ns);
        break;
    case BFD_STATE_INIT:
        if (remote_state == BFD_STATE_INIT || remote_state == BFD_STATE_UP)
            raw_state_transition(session, BFD_STATE_UP, "REMOTE_READY", now_ns);
        break;
    case BFD_STATE_UP:
        if (remote_state == BFD_STATE_DOWN || remote_state == BFD_STATE_ADMIN_DOWN)
            raw_state_transition(session, BFD_STATE_DOWN,
                                 remote_state == BFD_STATE_DOWN ? "REMOTE_DOWN"
                                                                : "REMOTE_ADMIN_DOWN",
                                 now_ns);
        break;
    case BFD_STATE_ADMIN_DOWN:
    default:
        break;
    }
}

static void receive_packets(struct bfd_manager *manager, uint64_t now_ns)
{
    for (;;) {
        struct bfd_control_packet packet;
        struct sockaddr_in source;
        struct msghdr msg;
        struct iovec iov;
        char control[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cmsg;
        struct in_addr destination = { .s_addr = 0 };
        unsigned int ifindex = 0;
        int ttl = -1;
        ssize_t received;

        memset(&source, 0, sizeof(source));
        memset(&msg, 0, sizeof(msg));
        memset(control, 0, sizeof(control));
        iov.iov_base = &packet;
        iov.iov_len = sizeof(packet);
        msg.msg_name = &source;
        msg.msg_namelen = sizeof(source);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        received = recvmsg(manager->rx_fd, &msg, MSG_DONTWAIT);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;
        }
        if ((msg.msg_flags & MSG_TRUNC) != 0)
            continue;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
                memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
            } else if (cmsg->cmsg_level == IPPROTO_IP &&
                       cmsg->cmsg_type == IP_PKTINFO) {
                const struct in_pktinfo *pktinfo =
                    (const struct in_pktinfo *)CMSG_DATA(cmsg);

                destination = pktinfo->ipi_addr;
                ifindex = (unsigned int)pktinfo->ipi_ifindex;
            }
        }
        if (destination.s_addr == 0)
            continue;
        process_packet(manager, &packet, (size_t)received, &source,
                       &destination, ifindex, ttl, now_ns);
    }
}

static void process_due_timers(struct bfd_manager *manager, uint64_t now_ns)
{
    size_t i;

    for (i = 0; i < manager->session_count; i++) {
        struct bfd_session *session = manager->sessions[i];

        if ((session->raw_state == BFD_STATE_INIT || session->raw_state == BFD_STATE_UP) &&
            session->detection_deadline_ns != 0 && now_ns >= session->detection_deadline_ns) {
            session->counters.timeouts++;
            raw_state_transition(session, BFD_STATE_DOWN, "DETECTION_TIMEOUT", now_ns);
        }
        stabilizer_tick(session, now_ns);
        if (now_ns >= session->next_tx_ns)
            (void)session_send(session, now_ns);
    }
}

static uint64_t session_next_deadline(const struct bfd_session *session)
{
    uint64_t deadline = session->next_tx_ns;

    if (session->detection_deadline_ns != 0 &&
        (deadline == 0 || session->detection_deadline_ns < deadline))
        deadline = session->detection_deadline_ns;
    if (session->stabilizer.deadline_ns != 0 &&
        (deadline == 0 || session->stabilizer.deadline_ns < deadline))
        deadline = session->stabilizer.deadline_ns;
    if (session->stabilizer.suppressed && session->stabilizer.config.half_life_ms != 0) {
        uint64_t decay = session->stabilizer.penalty_last_ns +
                         ms_to_ns(session->stabilizer.config.half_life_ms);
        if (deadline == 0 || decay < deadline)
            deadline = decay;
    }
    return deadline;
}

static int manager_wait_timeout_ms(const struct bfd_manager *manager,
                                   int requested_timeout_ms, uint64_t now_ns)
{
    uint64_t deadline = 0;
    size_t i;

    for (i = 0; i < manager->session_count; i++) {
        uint64_t candidate = session_next_deadline(manager->sessions[i]);
        if (candidate != 0 && (deadline == 0 || candidate < deadline))
            deadline = candidate;
    }
    if (deadline == 0 || deadline <= now_ns)
        return 0;

    {
        uint64_t wait_ms = (deadline - now_ns + UINT64_C(999999)) / UINT64_C(1000000);
        if (wait_ms > (uint64_t)requested_timeout_ms)
            return requested_timeout_ms;
        return wait_ms > (uint64_t)INT32_MAX ? INT32_MAX : (int)wait_ms;
    }
}

struct bfd_manager *bfd_manager_create(const struct in_addr *listen_ip)
{
    struct bfd_manager *manager;
    struct sockaddr_in address;
    struct epoll_event event;
    int one = 1;

    manager = calloc(1, sizeof(*manager));
    if (!manager)
        return NULL;
    manager->rx_fd = -1;
    manager->epoll_fd = -1;
    if (listen_ip)
        manager->listen_ip = *listen_ip;
    else
        manager->listen_ip.s_addr = htonl(INADDR_ANY);

    manager->rx_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (manager->rx_fd < 0)
        goto error;
    if (setsockopt(manager->rx_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
        setsockopt(manager->rx_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) < 0 ||
        setsockopt(manager->rx_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one)) < 0 ||
        set_nonblocking(manager->rx_fd) < 0)
        goto error;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(BFD_CONTROL_PORT);
    address.sin_addr = manager->listen_ip;
    if (bind(manager->rx_fd, (const struct sockaddr *)&address, sizeof(address)) < 0)
        goto error;

    manager->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (manager->epoll_fd < 0)
        goto error;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = manager->rx_fd;
    if (epoll_ctl(manager->epoll_fd, EPOLL_CTL_ADD, manager->rx_fd, &event) < 0)
        goto error;
    return manager;

error:
    bfd_manager_destroy(manager);
    return NULL;
}

void bfd_manager_destroy(struct bfd_manager *manager)
{
    size_t i;

    if (!manager)
        return;
    for (i = 0; i < manager->session_count; i++) {
        if (manager->sessions[i]->tx_fd >= 0)
            close(manager->sessions[i]->tx_fd);
        free(manager->sessions[i]);
    }
    if (manager->epoll_fd >= 0)
        close(manager->epoll_fd);
    if (manager->rx_fd >= 0)
        close(manager->rx_fd);
    free(manager);
}

struct bfd_session *bfd_manager_add_session(struct bfd_manager *manager,
                                             const struct bfd_session_config *config,
                                             const struct bfd_stability_config *stability,
                                             const struct bfd_callbacks *callbacks)
{
    struct bfd_session *session;
    int ttl = 255;

    if (!manager || !config || !stability || manager->session_count >= BFD_MAX_SESSIONS ||
        config->desired_min_tx_us < BFD_MIN_INTERVAL_US ||
        config->required_min_rx_us < BFD_MIN_INTERVAL_US || config->detect_mult == 0 ||
        (manager->listen_ip.s_addr != htonl(INADDR_ANY) &&
         config->local_ip.s_addr != manager->listen_ip.s_addr))
        return NULL;

    session = calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->manager = manager;
    session->tx_fd = -1;
    session->local_ip = config->local_ip;
    session->peer_ip = config->peer_ip;
    if (config->ifname && config->ifname[0] != '\0') {
        session->ifindex = if_nametoindex(config->ifname);
        if (session->ifindex == 0)
            goto error;
    }
    session->desired_min_tx_us = config->desired_min_tx_us;
    session->required_min_rx_us = config->required_min_rx_us;
    session->local_detect_mult = config->detect_mult;
    session->raw_state = BFD_STATE_DOWN;
    session->remote_state = BFD_STATE_DOWN;
    session->local_discriminator = nonzero_random_u32();
    session->prng = nonzero_random_u32();
    session->stabilizer.config = *stability;
    session->stabilizer.published = BFD_STABLE_DOWN;
    session->stabilizer.state = BFD_STABILIZER_IDLE;
    session->stabilizer.penalty_last_ns = monotonic_ns();
    if (callbacks)
        session->callbacks = *callbacks;
    if (config->ifname) {
        if (snprintf(session->ifname, sizeof(session->ifname), "%s", config->ifname) >=
            (int)sizeof(session->ifname))
            goto error;
    }

    session->tx_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (session->tx_fd < 0 ||
        setsockopt(session->tx_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
        goto error;
    if (session->ifname[0] != '\0' &&
        setsockopt(session->tx_fd, SOL_SOCKET, SO_BINDTODEVICE, session->ifname,
                   strlen(session->ifname) + 1U) < 0)
        goto error;

    if (bind_session_source(session) < 0)
        goto error;

    session->next_tx_ns = monotonic_ns();
    manager->sessions[manager->session_count++] = session;
    return session;

error:
    if (session->tx_fd >= 0)
        close(session->tx_fd);
    free(session);
    return NULL;
}

int bfd_manager_poll(struct bfd_manager *manager, int timeout_ms)
{
    struct epoll_event events[BFD_MAX_EVENTS];
    int count;
    int i;
    uint64_t now_ns;

    if (!manager || timeout_ms < 0)
        return -1;

    now_ns = monotonic_ns();
    process_due_timers(manager, now_ns);
    count = epoll_wait(manager->epoll_fd, events, BFD_MAX_EVENTS,
                       manager_wait_timeout_ms(manager, timeout_ms, monotonic_ns()));
    if (count < 0) {
        if (errno == EINTR)
            return 0;
        return -1;
    }
    now_ns = monotonic_ns();
    for (i = 0; i < count; i++) {
        if ((events[i].events & EPOLLIN) != 0)
            receive_packets(manager, now_ns);
    }
    process_due_timers(manager, monotonic_ns());
    return 0;
}

const char *bfd_session_ifname(const struct bfd_session *session)
{
    return session ? session->ifname : "";
}

const struct in_addr *bfd_session_local_ip(const struct bfd_session *session)
{
    return session ? &session->local_ip : NULL;
}

const struct in_addr *bfd_session_peer_ip(const struct bfd_session *session)
{
    return session ? &session->peer_ip : NULL;
}

enum bfd_state bfd_session_raw_state(const struct bfd_session *session)
{
    return session ? session->raw_state : BFD_STATE_ADMIN_DOWN;
}

enum bfd_stable_state bfd_session_published_state(const struct bfd_session *session)
{
    return session ? session->stabilizer.published : BFD_STABLE_UNKNOWN;
}

enum bfd_stabilizer_state bfd_session_stabilizer_state(const struct bfd_session *session)
{
    return session ? session->stabilizer.state : BFD_STABILIZER_IDLE;
}

uint32_t bfd_session_detection_time_us(const struct bfd_session *session)
{
    return session ? session->detection_time_us : 0;
}

uint32_t bfd_session_penalty(const struct bfd_session *session)
{
    return session ? session->stabilizer.penalty : 0;
}

bool bfd_session_is_suppressed(const struct bfd_session *session)
{
    return session && session->stabilizer.suppressed;
}

const struct bfd_counters *bfd_session_counters(const struct bfd_session *session)
{
    return session ? &session->counters : NULL;
}
