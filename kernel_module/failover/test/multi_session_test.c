#include "bfd.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_TIMEOUT_NS (UINT64_C(5) * UINT64_C(1000000000))

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int init_config(struct bfd_session_config *config,
                       const char *local_ip, const char *peer_ip)
{
    memset(config, 0, sizeof(*config));
    if (inet_pton(AF_INET, local_ip, &config->local_ip) != 1 ||
        inet_pton(AF_INET, peer_ip, &config->peer_ip) != 1)
        return -1;
    config->desired_min_tx_us = 300000U;
    config->required_min_rx_us = 300000U;
    config->detect_mult = 3U;
    return 0;
}

static int session_is_healthy(const struct bfd_session *session)
{
    const struct bfd_counters *counters = bfd_session_counters(session);

    return bfd_session_raw_state(session) == BFD_STATE_UP &&
           bfd_session_published_state(session) == BFD_STABLE_UP &&
           counters && counters->tx_packets > 0 && counters->rx_packets > 0;
}

int main(void)
{
    const struct bfd_stability_config stability = {0};
    struct bfd_session_config first_config;
    struct bfd_session_config second_config;
    struct bfd_manager *manager;
    struct bfd_session *first;
    struct bfd_session *second;
    uint64_t deadline;

    if (init_config(&first_config, "127.0.0.1", "127.0.0.2") < 0 ||
        init_config(&second_config, "127.0.0.2", "127.0.0.1") < 0)
        return EXIT_FAILURE;

    manager = bfd_manager_create();
    if (!manager) {
        perror("bfd_manager_create");
        return EXIT_FAILURE;
    }

    first = bfd_manager_add_session(manager, &first_config, &stability, NULL);
    second = bfd_manager_add_session(manager, &second_config, &stability, NULL);
    if (!first || !second) {
        fprintf(stderr, "failed to add sessions with different local IPs\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }
    if (bfd_manager_add_session(manager, &first_config, &stability, NULL)) {
        fprintf(stderr, "duplicate session was accepted\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }

    deadline = monotonic_ns() + TEST_TIMEOUT_NS;
    while (monotonic_ns() < deadline &&
           (!session_is_healthy(first) || !session_is_healthy(second))) {
        if (bfd_manager_poll(manager, 100) < 0) {
            perror("bfd_manager_poll");
            bfd_manager_destroy(manager);
            return EXIT_FAILURE;
        }
    }

    if (!session_is_healthy(first) || !session_is_healthy(second)) {
        fprintf(stderr, "sessions did not independently reach UP\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }

    printf("multi-session BFD test passed: first(rx=%" PRIu64 ",tx=%" PRIu64
           ") second(rx=%" PRIu64 ",tx=%" PRIu64 ")\n",
           bfd_session_counters(first)->rx_packets,
           bfd_session_counters(first)->tx_packets,
           bfd_session_counters(second)->rx_packets,
           bfd_session_counters(second)->tx_packets);
    bfd_manager_destroy(manager);
    return EXIT_SUCCESS;
}
