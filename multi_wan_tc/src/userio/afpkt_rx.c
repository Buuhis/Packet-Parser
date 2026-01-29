#include "userio/afpkt.h"
#include "utils/logger.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

static int bind_if(int fd, const char *ifname)
{
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(ifname);
    if (sll.sll_ifindex == 0) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        log_error("bind(%s) failed: %s", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int afpkt_rx_open(afpkt_rx_ctx_t *rx, const char *ifname,
                  size_t frame_nr, size_t frame_size)
{
    memset(rx, 0, sizeof(*rx));
    rx->frame_nr   = frame_nr;
    rx->frame_size = frame_size;
    rx->frame_idx  = 0;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        log_error("socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    int ver = TPACKET_V1;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0) {
        log_error("setsockopt(PACKET_VERSION) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* RX_RING */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_frame_nr   = (unsigned int)frame_nr;
    req.tp_frame_size = (unsigned int)frame_size;

    /* block sizes must be multiples; keep simple: 1 block = all frames */
    req.tp_block_size = req.tp_frame_size * req.tp_frame_nr;
    req.tp_block_nr   = 1;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
        log_error("setsockopt(PACKET_RX_RING) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (bind_if(fd, ifname) != 0) {
        close(fd);
        return -1;
    }

    size_t mmap_len = req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        log_error("mmap(rx_ring) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    rx->fd   = fd;
    rx->ring = ring;

    log_info("AF_PACKET RX ring ready on %s (frames=%zu frame_size=%zu)",
             ifname, frame_nr, frame_size);
    return 0;
}

void afpkt_rx_close(afpkt_rx_ctx_t *rx)
{
    if (!rx) return;
    if (rx->ring) {
        /* mmap length = frame_nr*frame_size (we used 1 block) */
        munmap(rx->ring, rx->frame_nr * rx->frame_size);
        rx->ring = NULL;
    }
    if (rx->fd > 0) {
        close(rx->fd);
        rx->fd = -1;
    }
}

int afpkt_rx_poll_count(afpkt_rx_ctx_t *rx)
{
    struct pollfd pfd = { .fd = rx->fd, .events = POLLIN };
    static unsigned long pkt_cnt = 0;

    int ret = poll(&pfd, 1, 1000);
    if (ret <= 0)
        return 0;

    int got = 0;

    while (1) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr *)((char *)rx->ring + (rx->frame_idx * rx->frame_size));

        if (!(hdr->tp_status & TP_STATUS_USER))
            break;

        /* L2 pointer (not used now, RX-2 only) */
        // unsigned char *frame = (unsigned char *)hdr + hdr->tp_mac;
        // unsigned int len = hdr->tp_len;

        pkt_cnt++;
        got++;

        hdr->tp_status = TP_STATUS_KERNEL;
        rx->frame_idx = (rx->frame_idx + 1) % rx->frame_nr;
    }

    if (pkt_cnt && (pkt_cnt % 1000 == 0)) {
        log_info("RX-2 AF_PACKET captured packets=%lu", pkt_cnt);
    }

    return got;
}
