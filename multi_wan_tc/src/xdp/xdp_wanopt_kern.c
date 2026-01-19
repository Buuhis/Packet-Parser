// clang -O2 -g -target bpf -c xdp_wanopt_kern.c -o xdp_wanopt_kern.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_wanopt_kern.h"

/*
 * XSK map: key = RX queue id, value = AF_XDP socket fd (userspace sẽ update)
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);     // đủ cho NIC nhiều queue
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

/*
 * Step 7A-1: redirect tất cả packet nhận trên local_if vào AF_XDP socket
 * - Nếu queue chưa bind XSK => XDP_PASS (kernel xử lý bình thường)
 */
SEC("xdp")
int xdp_wanopt_capture(struct xdp_md *ctx)
{
    __u32 qid = ctx->rx_queue_index;

    // Nếu userspace đã gắn XSK vào queue này, redirect vào userspace
    if (bpf_map_lookup_elem(&xsk_map, &qid)) {
        return bpf_redirect_map(&xsk_map, qid, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

