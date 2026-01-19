#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../utils/logger.h"
#include "../xdp/xdp_wanopt_kern.h"

static volatile int running = 1;

static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

/*
 * Step 7A-1 userspace responsibilities:
 * 1) load xdp object
 * 2) attach to ifindex
 * 3) find xsk_map fd
 * 4) create AF_XDP socket for queue 0 (TODO)
 * 5) update xsk_map[qid] = xsk_socket_fd
 * 6) poll/recv packets (TODO)
 *
 * NOTE: phần create XSK + rings sẽ implement ở 7A-2 (pass-through).
 * Ở 7A-1, bạn có thể:
 * - tạo XSK với libxdp/xsk.h (khuyến nghị)
 * - hoặc tự setup umem/rings
 */
int xsk_capture_attach(const char *ifname, const char *bpf_obj_path, int qid)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        log_error("if_nametoindex(%s) failed", ifname);
        return -1;
    }

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1;
    int map_fd = -1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        log_error("bpf_object__open_file failed: %s", bpf_obj_path);
        return -1;
    }

    if (bpf_object__load(obj) != 0) {
        log_error("bpf_object__load failed");
        bpf_object__close(obj);
        return -1;
    }

    // lấy program "xdp"
    prog = bpf_object__find_program_by_name(obj, "xdp_wanopt_capture");
    if (!prog) {
        log_error("cannot find program xdp_wanopt_capture");
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        log_error("bpf_program__fd failed");
        bpf_object__close(obj);
        return -1;
    }

    // attach XDP (native mode)
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        log_error("bpf_set_link_xdp_fd failed: %s", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }
    log_info("XDP attached on %s (ifindex=%d)", ifname, ifindex);

    // find XSK map
    struct bpf_map *m = bpf_object__find_map_by_name(obj, XDP_WANOPT_XSK_MAP_NAME);
    if (!m) {
        log_error("cannot find map: %s", XDP_WANOPT_XSK_MAP_NAME);
        // detach before exit
        bpf_set_link_xdp_fd(ifindex, -1, 0);
        bpf_object__close(obj);
        return -1;
    }
    map_fd = bpf_map__fd(m);

    /*
     * TODO (7A-1 minimal requirement):
     * - Create AF_XDP socket bound to (ifname, qid)
     * - Get xsk_fd
     * - bpf_map_update_elem(map_fd, &qid, &xsk_fd, 0)
     *
     * Ở 7A-2 mình sẽ đưa full code XSK (umem + rings + recv loop).
     */
    log_info("Loaded XDP obj OK. Next: create XSK and update xsk_map[qid=%d].", qid);

    // Giữ obj sống để prog/map không bị unload
    // (sau này bạn gắn vào app_context và run loop)
    while (running) {
        sleep(1);
    }

    log_info("Detaching XDP...");
    bpf_set_link_xdp_fd(ifindex, -1, 0);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <bpf_obj>\n", argv[0]);
        return 2;
    }
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    const char *ifname = argv[1];
    const char *obj = argv[2];

    return xsk_capture_attach(ifname, obj, 0);
}

