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
           !bfd_session_poll_active(session) &&
           bfd_session_detection_time_us(session) == 900000U &&
           bfd_session_source_port(session) >= 49152U &&
           counters && counters->tx_packets > 0 && counters->rx_packets > 0;
}

int main(void)
{
    const struct bfd_stability_config stability = {0};
    static const char *const local_ips[] = {
        "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"
    };
    static const char *const peer_ips[] = {
        "127.0.0.2", "127.0.0.1", "127.0.0.4", "127.0.0.3"
    };
    struct bfd_session_config configs[4];
    struct bfd_session *sessions[4] = {0};
    struct bfd_manager *manager;
    uint64_t deadline;
    size_t i;

    for (i = 0; i < 4; i++) {
        if (init_config(&configs[i], local_ips[i], peer_ips[i]) < 0)
            return EXIT_FAILURE;
    }

    manager = bfd_manager_create();
    if (!manager) {
        perror("bfd_manager_create");
        return EXIT_FAILURE;
    }

    for (i = 0; i < 4; i++) {
        sessions[i] = bfd_manager_add_session(manager, &configs[i],
                                              &stability, NULL);
        if (!sessions[i]) {
            fprintf(stderr, "failed to add session %zu\n", i);
            bfd_manager_destroy(manager);
            return EXIT_FAILURE;
        }
    }
    if (bfd_manager_add_session(manager, &configs[0], &stability, NULL)) {
        fprintf(stderr, "duplicate session was accepted\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }

    deadline = monotonic_ns() + TEST_TIMEOUT_NS;
    while (monotonic_ns() < deadline) {
        bool all_healthy = true;

        for (i = 0; i < 4; i++)
            all_healthy = all_healthy && session_is_healthy(sessions[i]);
        if (all_healthy)
            break;
        if (bfd_manager_poll(manager, 100) < 0) {
            perror("bfd_manager_poll");
            bfd_manager_destroy(manager);
            return EXIT_FAILURE;
        }
    }

    for (i = 0; i < 4; i++) {
        if (!session_is_healthy(sessions[i])) {
            fprintf(stderr, "session %zu did not independently reach UP\n", i);
            bfd_manager_destroy(manager);
            return EXIT_FAILURE;
        }
    }

    printf("multi-session BFD test passed:");
    for (i = 0; i < 4; i++) {
        printf(" s%zu(rx=%" PRIu64 ",tx=%" PRIu64 ")", i + 1,
               bfd_session_counters(sessions[i])->rx_packets,
               bfd_session_counters(sessions[i])->tx_packets);
    }
    printf("\n");

    if (bfd_manager_remove_session(manager, sessions[0]) < 0 ||
        bfd_manager_remove_session(manager, sessions[1]) < 0) {
        fprintf(stderr, "failed to remove sessions incrementally\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }
    sessions[0] = NULL;
    sessions[1] = NULL;
    if (bfd_manager_poll(manager, 100) < 0 ||
        !session_is_healthy(sessions[2]) ||
        !session_is_healthy(sessions[3])) {
        fprintf(stderr, "remaining sessions changed after incremental removal\n");
        bfd_manager_destroy(manager);
        return EXIT_FAILURE;
    }
    bfd_manager_destroy(manager);
    return EXIT_SUCCESS;
}
