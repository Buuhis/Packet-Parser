#include "bfd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t stop_requested;

struct test_options {
    struct in_addr bind_ip;
    struct in_addr peer_ip;
    const char *ifname;
    uint32_t tx_ms;
    uint32_t rx_ms;
    uint32_t duration_s;
    uint8_t detect_mult;
    struct bfd_stability_config stability;
};

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void request_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static const char *session_ip(const struct in_addr *ip, char buffer[INET_ADDRSTRLEN])
{
    return inet_ntop(AF_INET, ip, buffer, INET_ADDRSTRLEN) ? buffer : "<invalid-ip>";
}

static void raw_state_changed(const struct bfd_session *session,
                              enum bfd_state old_state,
                              enum bfd_state new_state,
                              const char *reason,
                              void *user)
{
    char local[INET_ADDRSTRLEN];
    char peer[INET_ADDRSTRLEN];

    (void)user;
    printf("[BFD raw] local=%s peer=%s if=%s %s -> %s reason=%s detect=%" PRIu32 "us\n",
           session_ip(bfd_session_local_ip(session), local),
           session_ip(bfd_session_peer_ip(session), peer),
           bfd_session_ifname(session)[0] ? bfd_session_ifname(session) : "(none)",
           bfd_state_name(old_state), bfd_state_name(new_state), reason,
           bfd_session_detection_time_us(session));
    fflush(stdout);
}

static void published_state_changed(const struct bfd_session *session,
                                    enum bfd_stable_state old_state,
                                    enum bfd_stable_state new_state,
                                    void *user)
{
    char peer[INET_ADDRSTRLEN];

    (void)user;
    printf("[BFD published] peer=%s %s -> %s stabilizer=%s penalty=%" PRIu32
           " suppressed=%s\n",
           session_ip(bfd_session_peer_ip(session), peer),
           bfd_stable_state_name(old_state), bfd_stable_state_name(new_state),
           bfd_stabilizer_state_name(bfd_session_stabilizer_state(session)),
           bfd_session_penalty(session),
           bfd_session_is_suppressed(session) ? "yes" : "no");
    fflush(stdout);
}

static int parse_u32(const char *text, uint32_t min, uint32_t max, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < min || parsed > max)
        return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static void usage(const char *program)
{
    printf("Usage: %s --bind IPv4 --peer IPv4 [options]\n", program);
    printf("\n");
    printf("Run one instance on each endpoint device. Both peers must use\n");
    printf("the same tx/rx interval and detect multiplier during the standalone test.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --interface NAME       Bind outgoing BFD packets to NAME (optional)\n");
    printf("  --tx-ms N              Desired TX interval after UP; default 300\n");
    printf("  --rx-ms N              Required RX interval; default 300\n");
    printf("  --detect-mult N        BFD detection multiplier; default 3\n");
    printf("  --up-hold-ms N         Continuous raw-UP time before published UP; default 5000\n");
    printf("  --down-hold-ms N       Continuous raw-DOWN time before published DOWN; default 0\n");
    printf("  --half-life-ms N       Penalty half-life; default 15000 (0 disables damping)\n");
    printf("  --flap-penalty N       Penalty for a raw UP->DOWN; default 1000\n");
    printf("  --suppress N           Penalty that suppresses recovery; default 2000\n");
    printf("  --reuse N              Penalty below which recovery resumes; default 750\n");
    printf("  --duration-s N         Test duration; 0 means until Ctrl-C; default 30\n");
    printf("\n");
    printf("Local multi-session smoke test:\n");
    printf("  make check\n");
}

int main(int argc, char **argv)
{
    static const struct option long_options[] = {
        { "bind",         required_argument, NULL, 'b' },
        { "peer",         required_argument, NULL, 'p' },
        { "interface",    required_argument, NULL, 'i' },
        { "tx-ms",        required_argument, NULL, 1 },
        { "rx-ms",        required_argument, NULL, 2 },
        { "detect-mult",  required_argument, NULL, 3 },
        { "up-hold-ms",   required_argument, NULL, 4 },
        { "down-hold-ms", required_argument, NULL, 5 },
        { "half-life-ms", required_argument, NULL, 6 },
        { "flap-penalty", required_argument, NULL, 7 },
        { "suppress",     required_argument, NULL, 8 },
        { "reuse",        required_argument, NULL, 9 },
        { "duration-s",   required_argument, NULL, 10 },
        { "help",         no_argument,       NULL, 'h' },
        { NULL,            0,                 NULL, 0 },
    };
    struct test_options options = {
        .tx_ms = 300,
        .rx_ms = 300,
        .duration_s = 30,
        .detect_mult = 3,
        .stability = {
            .up_hold_ms = 5000,
            .down_hold_ms = 0,
            .half_life_ms = 15000,
            .flap_penalty = 1000,
            .suppress_threshold = 2000,
            .reuse_threshold = 750,
        },
    };
    struct bfd_session_config config;
    struct bfd_callbacks callbacks = {
        .raw_state_changed = raw_state_changed,
        .published_state_changed = published_state_changed,
        .user = NULL,
    };
    struct bfd_manager *manager;
    struct bfd_session *session;
    uint64_t deadline_ns = 0;
    int option;
    bool have_bind = false;
    bool have_peer = false;

    while ((option = getopt_long(argc, argv, "b:p:i:h", long_options, NULL)) != -1) {
        uint32_t parsed;

        switch (option) {
        case 'b':
            have_bind = inet_pton(AF_INET, optarg, &options.bind_ip) == 1;
            if (!have_bind) {
                fprintf(stderr, "Invalid --bind IPv4 address: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'p':
            have_peer = inet_pton(AF_INET, optarg, &options.peer_ip) == 1;
            if (!have_peer) {
                fprintf(stderr, "Invalid --peer IPv4 address: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'i':
            options.ifname = optarg;
            break;
        case 1:
            if (parse_u32(optarg, 1, UINT32_MAX / 1000U, &options.tx_ms) < 0)
                goto invalid_number;
            break;
        case 2:
            if (parse_u32(optarg, 1, UINT32_MAX / 1000U, &options.rx_ms) < 0)
                goto invalid_number;
            break;
        case 3:
            if (parse_u32(optarg, 1, UINT8_MAX, &parsed) < 0)
                goto invalid_number;
            options.detect_mult = (uint8_t)parsed;
            break;
        case 4:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.up_hold_ms) < 0)
                goto invalid_number;
            break;
        case 5:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.down_hold_ms) < 0)
                goto invalid_number;
            break;
        case 6:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.half_life_ms) < 0)
                goto invalid_number;
            break;
        case 7:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.flap_penalty) < 0)
                goto invalid_number;
            break;
        case 8:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.suppress_threshold) < 0)
                goto invalid_number;
            break;
        case 9:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.stability.reuse_threshold) < 0)
                goto invalid_number;
            break;
        case 10:
            if (parse_u32(optarg, 0, UINT32_MAX, &options.duration_s) < 0)
                goto invalid_number;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        continue;

invalid_number:
        fprintf(stderr, "Invalid numeric value for option: %s\n", optarg);
        return EXIT_FAILURE;
    }
    if (!have_bind || !have_peer || optind != argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (options.stability.suppress_threshold != 0 &&
        options.stability.reuse_threshold > options.stability.suppress_threshold) {
        fprintf(stderr, "--reuse must not exceed --suppress\n");
        return EXIT_FAILURE;
    }

    memset(&config, 0, sizeof(config));
    config.ifname = options.ifname;
    config.local_ip = options.bind_ip;
    config.peer_ip = options.peer_ip;
    config.desired_min_tx_us = options.tx_ms * 1000U;
    config.required_min_rx_us = options.rx_ms * 1000U;
    config.detect_mult = options.detect_mult;

    manager = bfd_manager_create();
    if (!manager) {
        perror("bfd_manager_create");
        return EXIT_FAILURE;
    }
    session = bfd_manager_add_session(manager, &config, &options.stability, &callbacks);
    if (!session) {
        perror("bfd_manager_add_session");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }

    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    if (options.duration_s != 0)
        deadline_ns = monotonic_ns() + (uint64_t)options.duration_s * UINT64_C(1000000000);
    printf("[BFD test] started; Ctrl-C or --duration-s ends the test\n");
    fflush(stdout);

    while (!stop_requested && (deadline_ns == 0 || monotonic_ns() < deadline_ns)) {
        if (bfd_manager_poll(manager, 1000) < 0) {
            perror("bfd_manager_poll");
            bfd_manager_destroy(manager);
            return EXIT_FAILURE;
        }
    }

    {
        const struct bfd_counters *counters = bfd_session_counters(session);
        printf("[BFD test] final raw=%s published=%s stabilizer=%s tx=%" PRIu64
               " rx=%" PRIu64 " timeouts=%" PRIu64 " invalid=%" PRIu64
               " ttl_drops=%" PRIu64 " transitions(raw/published)=%" PRIu64 "/%" PRIu64 "\n",
               bfd_state_name(bfd_session_raw_state(session)),
               bfd_stable_state_name(bfd_session_published_state(session)),
               bfd_stabilizer_state_name(bfd_session_stabilizer_state(session)),
               counters->tx_packets, counters->rx_packets, counters->timeouts,
               counters->invalid_packets, counters->ttl_drops,
               counters->raw_state_transitions, counters->published_state_transitions);
    }
    bfd_manager_destroy(manager);
    return EXIT_SUCCESS;
}
