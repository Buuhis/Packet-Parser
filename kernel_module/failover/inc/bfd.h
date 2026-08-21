#ifndef SDWAN_FAILOVER_BFD_H
#define SDWAN_FAILOVER_BFD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#define BFD_CONTROL_PORT 3784U
#define BFD_CONTROL_LEN  24U

enum bfd_state {
    BFD_STATE_ADMIN_DOWN = 0,
    BFD_STATE_DOWN       = 1,
    BFD_STATE_INIT       = 2,
    BFD_STATE_UP         = 3,
};

enum bfd_stable_state {
    BFD_STABLE_UNKNOWN = 0,
    BFD_STABLE_DOWN,
    BFD_STABLE_UP,
};

enum bfd_stabilizer_state {
    BFD_STABILIZER_IDLE = 0,
    BFD_STABILIZER_DOWN_PENDING,
    BFD_STABILIZER_UP_PENDING,
    BFD_STABILIZER_SUPPRESSED,
};

/* RFC 5880, section 4.1.  Authentication is deliberately not included. */
struct bfd_control_packet {
    uint8_t version_diag;
    uint8_t state_flags;
    uint8_t detect_mult;
    uint8_t length;
    uint32_t my_discriminator;
    uint32_t your_discriminator;
    uint32_t desired_min_tx;
    uint32_t required_min_rx;
    uint32_t required_min_echo_rx;
} __attribute__((packed));

struct bfd_session_config {
    const char *ifname;             /* Optional.  Empty means do not bind to a device. */
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint32_t desired_min_tx_us;     /* Used after the session reaches UP. */
    uint32_t required_min_rx_us;
    uint8_t detect_mult;
};

struct bfd_stability_config {
    uint32_t up_hold_ms;
    uint32_t down_hold_ms;
    uint32_t half_life_ms;          /* Zero disables penalty decay/dampening. */
    uint32_t flap_penalty;
    uint32_t suppress_threshold;
    uint32_t reuse_threshold;
};

struct bfd_manager;
struct bfd_session;

typedef void (*bfd_raw_state_callback)(const struct bfd_session *session,
                                       enum bfd_state old_state,
                                       enum bfd_state new_state,
                                       const char *reason,
                                       void *user);
typedef void (*bfd_published_state_callback)(const struct bfd_session *session,
                                             enum bfd_stable_state old_state,
                                             enum bfd_stable_state new_state,
                                             void *user);

struct bfd_callbacks {
    bfd_raw_state_callback raw_state_changed;
    bfd_published_state_callback published_state_changed;
    void *user;
};

struct bfd_counters {
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t invalid_packets;
    uint64_t ttl_drops;
    uint64_t discriminator_drops;
    uint64_t peer_drops;
    uint64_t timeouts;
    uint64_t raw_state_transitions;
    uint64_t published_state_transitions;
};

/* listen_ip selects a single-address standalone manager. NULL binds
 * INADDR_ANY; sessions are then demultiplexed by IP_PKTINFO for production. */
struct bfd_manager *bfd_manager_create(const struct in_addr *listen_ip);
void bfd_manager_destroy(struct bfd_manager *manager);

struct bfd_session *bfd_manager_add_session(struct bfd_manager *manager,
                                             const struct bfd_session_config *config,
                                             const struct bfd_stability_config *stability,
                                             const struct bfd_callbacks *callbacks);

/* Process packets and due timers. timeout_ms is an upper bound, not a promise. */
int bfd_manager_poll(struct bfd_manager *manager, int timeout_ms);

const char *bfd_state_name(enum bfd_state state);
const char *bfd_stable_state_name(enum bfd_stable_state state);
const char *bfd_stabilizer_state_name(enum bfd_stabilizer_state state);

const char *bfd_session_ifname(const struct bfd_session *session);
const struct in_addr *bfd_session_local_ip(const struct bfd_session *session);
const struct in_addr *bfd_session_peer_ip(const struct bfd_session *session);
enum bfd_state bfd_session_raw_state(const struct bfd_session *session);
enum bfd_stable_state bfd_session_published_state(const struct bfd_session *session);
enum bfd_stabilizer_state bfd_session_stabilizer_state(const struct bfd_session *session);
uint32_t bfd_session_detection_time_us(const struct bfd_session *session);
uint32_t bfd_session_penalty(const struct bfd_session *session);
bool bfd_session_is_suppressed(const struct bfd_session *session);
const struct bfd_counters *bfd_session_counters(const struct bfd_session *session);

#endif /* SDWAN_FAILOVER_BFD_H */
