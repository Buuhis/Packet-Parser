#define _GNU_SOURCE
#define _POSIX_C_SOURCE 202504L

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <poll.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include "../utils/logger.h"
#include "../xdp/xdp_wanopt_kern.h"

static volatile int running = 1;

static void on_sigint(int sig)
{
    (void)sig;
    running = 0;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        log_error("setrlimit(RLIMIT_MEMLOCK) failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

struct xsk_ctx {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;

    void *umem_area;
    size_t umem_size;

    struct xsk_ring_cons rx;
    struct xsk_ring_prod fq;

    int ifindex;
    int qid;
    int xsk_fd;

    int xdp_prog_fd;
    int xdp_map_fd;
    struct bpf_object *bpf_obj;

    __u64 rx_pkts;
    __u64 rx_bytes;
};

static int umem_create(struct xsk_ctx *c, int frame_size, int frame_count)
{
    // UMEM size
    c->umem_size = (size_t)frame_size * (size_t)frame_count;

    // page-aligned mmap
    c->umem_area = mmap(NULL, c->umem_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (c->umem_area == MAP_FAILED) {
        log_error("mmap UMEM failed: %s", strerror(errno));
        return -1;
    }

    struct xsk_umem_config cfg = {
        .fill_size = 2048,
        .comp_size = 0,        // 7A-2: chỉ RX, chưa cần completion ring
        .frame_size = frame_size,
        .frame_headroom = 0,
        .flags = 0,
    };

    int err = xsk_umem__create(&c->umem, c->umem_area, c->umem_size,
                              &c->fq, NULL, &cfg);
    if (err) {
        log_error("xsk_umem__create failed: %s", strerror(-err));
        munmap(c->umem_area, c->umem_size);
        c->umem_area = NULL;
        return -1;
    }

    // Put all frames into FQ so kernel can DMA packets into them
    __u32 idx;
    int n = xsk_ring_prod__reserve(&c->fq, frame_count, &idx);
    if (n != frame_count) {
        log_error("reserve FQ failed: reserved=%d expected=%d", n, frame_count);
        return -1;
    }

    for (int i = 0; i < frame_count; i++) {
        __u64 addr = (__u64)i * (__u64)frame_size;
        *xsk_ring_prod__fill_addr(&c->fq, idx + i) = addr;
    }
    xsk_ring_prod__submit(&c->fq, frame_count);

    log_info("UMEM created: frame_size=%d frame_count=%d", frame_size, frame_count);
    return 0;
}

static int xsk_create(struct xsk_ctx *c, const char *ifname, int qid)
{
    c->qid = qid;
    c->ifindex = if_nametoindex(ifname);
    if (!c->ifindex) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    // 7A-2: dùng SKB mode để dễ chạy trên nhiều NIC (compat)
    // Sau này muốn performance thì chuyển sang DRV/ZEROCOPY.
    struct xsk_socket_config xcfg = {
        .rx_size = 2048,
        .tx_size = 0,          // 7A-2 chỉ RX
        .libbpf_flags = 0,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY, // SKB mode thường dùng copy; về sau đổi ZEROCOPY nếu NIC hỗ trợ
    };

    int err = xsk_socket__create(&c->xsk, ifname, qid, c->umem,
                                 &c->rx, NULL, &xcfg);
    if (err) {
        log_error("xsk_socket__create failed: %s", strerror(-err));
        return -1;
    }

    c->xsk_fd = xsk_socket__fd(c->xsk);
    log_info("XSK created: if=%s qid=%d xsk_fd=%d", ifname, qid, c->xsk_fd);
    return 0;
}

static int load_and_attach_xdp(struct xsk_ctx *c, const char *ifname, const char *obj_path)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    c->bpf_obj = bpf_object__open_file(obj_path, NULL);
    if (!c->bpf_obj) {
        log_error("bpf_object__open_file failed: %s", obj_path);
        return -1;
    }

    if (bpf_object__load(c->bpf_obj) != 0) {
        log_error("bpf_object__load failed");
        bpf_object__close(c->bpf_obj);
        c->bpf_obj = NULL;
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(c->bpf_obj, "xdp_wanopt_capture");
    if (!prog) {
        log_error("cannot find program xdp_wanopt_capture");
        return -1;
    }
    c->xdp_prog_fd = bpf_program__fd(prog);

    // attach XDP on local_if
    int err = bpf_set_link_xdp_fd(ifindex, c->xdp_prog_fd, XDP_FLAGS_SKB_MODE);
    if (err < 0) {
        log_error("bpf_set_link_xdp_fd failed: %s", strerror(-err));
        return -1;
    }
    log_info("XDP attached on %s (ifindex=%d) [SKB mode]", ifname, ifindex);

    // map fd
    struct bpf_map *m = bpf_object__find_map_by_name(c->bpf_obj, XDP_WANOPT_XSK_MAP_NAME);
    if (!m) {
        log_error("cannot find map: %s", XDP_WANOPT_XSK_MAP_NAME);
        return -1;
    }
    c->xdp_map_fd = bpf_map__fd(m);
    return 0;
}

static int update_xsk_map(struct xsk_ctx *c)
{
    __u32 key = (__u32)c->qid;
    __u32 val = (__u32)c->xsk_fd;
    if (bpf_map_update_elem(c->xdp_map_fd, &key, &val, 0) != 0) {
        log_error("bpf_map_update_elem(xsk_map[%u]=%u) failed: %s", key, val, strerror(errno));
        return -1;
    }
    log_info("xsk_map updated: qid=%u -> xsk_fd=%u", key, val);
    return 0;
}

static void detach_xdp(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return;

    // detach any XDP
    bpf_set_link_xdp_fd(ifindex, -1, 0);
}

static void stats_print(struct xsk_ctx *c, __u64 last_pkts, __u64 last_bytes, double dt)
{
    __u64 pkts  = c->rx_pkts - last_pkts;
    __u64 bytes = c->rx_bytes - last_bytes;

    double pps = dt > 0 ? (double)pkts / dt : 0;
    double bps = dt > 0 ? (double)bytes * 8.0 / dt : 0;

    log_info("RX: total_pkts=%llu total_bytes=%llu | pps=%.0f bps=%.0f",
             (unsigned long long)c->rx_pkts,
             (unsigned long long)c->rx_bytes,
             pps, bps);
}

static int recv_loop(struct xsk_ctx *c)
{
    struct pollfd pfd = {
        .fd = c->xsk_fd,
        .events = POLLIN,
    };

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    __u64 last_pkts = 0, last_bytes = 0;

    while (running) {
        int ret = poll(&pfd, 1, 100); // 100ms
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            log_error("poll failed: %s", strerror(errno));
            return -1;
        }

        // Try to consume RX descriptors
        __u32 idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&c->rx, 64, &idx_rx);
        if (rcvd > 0) {
            for (unsigned int i = 0; i < rcvd; i++) {
                struct xdp_desc *d = xsk_ring_cons__rx_desc(&c->rx, idx_rx + i);
                __u64 addr = d->addr;
                __u32 len  = d->len;

                c->rx_pkts++;
                c->rx_bytes += len;

                // recycle frame back to fill queue
                __u32 idx_fq;
                while (xsk_ring_prod__reserve(&c->fq, 1, &idx_fq) != 1) {
                    // FQ full - should be rare; yield a bit
                    // (Kernel not consuming fast enough; but in RX-only, usually OK)
                    sched_yield();
                }
                *xsk_ring_prod__fill_addr(&c->fq, idx_fq) = addr;
                xsk_ring_prod__submit(&c->fq, 1);
            }

            xsk_ring_cons__release(&c->rx, rcvd);
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (dt >= 1.0) {
            stats_print(c, last_pkts, last_bytes, dt);
            last_pkts = c->rx_pkts;
            last_bytes = c->rx_bytes;
            t0 = t1;
        }
    }

    return 0;
}

static void xsk_cleanup(struct xsk_ctx *c)
{
    if (c->xsk) {
        xsk_socket__delete(c->xsk);
        c->xsk = NULL;
    }

    if (c->umem) {
        xsk_umem__delete(c->umem);
        c->umem = NULL;
    }

    if (c->umem_area) {
        munmap(c->umem_area, c->umem_size);
        c->umem_area = NULL;
        c->umem_size = 0;
    }

    if (c->bpf_obj) {
        bpf_object__close(c->bpf_obj);
        c->bpf_obj = NULL;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <ifname> <bpf_obj> [qid]\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    const char *ifname = argv[1];
    const char *obj    = argv[2];
    int qid = 0;
    if (argc >= 4)
        qid = atoi(argv[3]);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    log_set_level(LOG_INFO);

    if (bump_memlock_rlimit() != 0)
        return 1;

    struct xsk_ctx c;
    memset(&c, 0, sizeof(c));

    // 1) Load & attach XDP
    if (load_and_attach_xdp(&c, ifname, obj) != 0) {
        log_error("Failed to load/attach XDP");
        goto out;
    }

    // 2) Create UMEM
    // frame_size 2048, frame_count 4096 (tùy NIC/traffic, đủ cho test)
    if (umem_create(&c, 2048, 4096) != 0) {
        log_error("Failed to create UMEM");
        goto out_detach;
    }

    // 3) Create XSK (bind queue)
    if (xsk_create(&c, ifname, qid) != 0) {
        log_error("Failed to create XSK");
        goto out_detach;
    }

    // 4) Update xsk_map[qid] = xsk_fd (từ đây IPv4 sẽ bắt đầu đi vào userspace)
    if (update_xsk_map(&c) != 0) {
        log_error("Failed to update xsk_map");
        goto out_detach;
    }

    log_info("7A-2 running: IPv4 packets on %s (qid=%d) redirected to userspace. Ctrl+C to stop.",
             ifname, qid);

    // 5) Recv loop
    int rc = recv_loop(&c);

out_detach:
    log_info("Detaching XDP...");
    detach_xdp(ifname);

out:
    xsk_cleanup(&c);
    return rc == 0 ? 0 : 1;
}

