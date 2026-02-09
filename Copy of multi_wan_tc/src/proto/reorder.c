#define _GNU_SOURCE
#include "mwan_proto.h"
#include "utils/logger.h"

#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

void reorder_init(reorder_ctx_t *ctx)
{
    atomic_store(&ctx->expected_seq, 0);
    for (int i = 0; i < REORDER_WINDOW; i++) {
        atomic_store(&ctx->slots[i].state, 0);
        ctx->slots[i].len = 0;
    }
}

void reorder_insert(reorder_ctx_t *ctx, uint32_t seq,
                    const uint8_t *ip_data, uint16_t ip_len)
{
    uint32_t expected = atomic_load(&ctx->expected_seq);

    /* If seq is too far behind expected, it's a late/duplicate packet — drop */
    if (seq < expected && (expected - seq) < REORDER_WINDOW) {
        return;  /* Already forwarded */
    }

    /* If seq is too far ahead, it would overflow the window — drop */
    if (seq >= expected + REORDER_WINDOW) {
        return;  /* Too far ahead */
    }

    uint32_t idx = seq % REORDER_WINDOW;
    reorder_slot_t *slot = &ctx->slots[idx];

    /* Only write if slot is empty (avoid overwrite race) */
    int empty = 0;
    if (atomic_compare_exchange_strong(&slot->state, &empty, 0)) {
        memcpy(slot->data, ip_data, ip_len);
        slot->len = ip_len;
        slot->insert_time_ns = mwan_now_ns();
        atomic_store(&slot->state, 1);  /* Mark ready with release semantics */
    }
}

/*
 * Build and send an Ethernet frame with the reassembled IP packet.
 */
static void send_packet(reorder_ctx_t *ctx,
                        const uint8_t *ip_data, uint16_t ip_len)
{
    uint8_t frame[14 + 1500];  /* Eth header + IP packet */

    /* Build Ethernet header */
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, ctx->lan_dst_mac, 6);
    memcpy(eth->h_source, ctx->local_src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* Copy IP data */
    memcpy(frame + 14, ip_data, ip_len);

    uint16_t frame_len = 14 + ip_len;

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex  = ctx->local_ifindex;
    sa.sll_halen    = 6;
    memcpy(sa.sll_addr, ctx->lan_dst_mac, 6);

    sendto(ctx->tx_fd, frame, frame_len, 0,
           (struct sockaddr *)&sa, sizeof(sa));
}

void reorder_output_loop(reorder_ctx_t *ctx)
{
    log_info("Reorder output thread started");

    uint64_t last_activity_ns = mwan_now_ns();

    while (*ctx->running) {
        uint32_t expected = atomic_load(&ctx->expected_seq);
        uint32_t idx = expected % REORDER_WINDOW;
        reorder_slot_t *slot = &ctx->slots[idx];

        int state = atomic_load(&slot->state);

        if (state == 1) {
            /* Packet ready — send it */
            send_packet(ctx, slot->data, slot->len);

            /* Clear slot and advance */
            slot->len = 0;
            atomic_store(&slot->state, 0);
            atomic_fetch_add(&ctx->expected_seq, 1);

            last_activity_ns = mwan_now_ns();
            continue;  /* Check next slot immediately */
        }

        /* Slot not ready — check timeout */
        uint64_t now = mwan_now_ns();
        if ((now - last_activity_ns) > REORDER_TIMEOUT_NS) {
            /* Timeout: skip this seq (packet lost or too late) */
            atomic_fetch_add(&ctx->expected_seq, 1);
            last_activity_ns = now;
            continue;
        }

        /* Brief pause to avoid busy-spinning */
        usleep(10);  /* 10us */
    }

    log_info("Reorder output thread stopped");
}
