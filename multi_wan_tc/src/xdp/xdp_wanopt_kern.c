// clang -O2 -g -target bpf -c xdp_wanopt_kern.c -o xdp_wanopt_kern.o
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#include "xdp_wanopt_kern.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

static __always_inline int is_ipv4(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return 0;

    return 1;
}

SEC("xdp")
int xdp_wanopt_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // an toàn: chỉ redirect IPv4, còn lại PASS
    if (!is_ipv4(data, data_end))
        return XDP_PASS;

    __u32 qid = ctx->rx_queue_index;

    // Nếu queue có XSK bind -> redirect vào userspace
    // Nếu chưa bind -> PASS (không đứt mạng)
    if (bpf_map_lookup_elem(&xsk_map, &qid))
        return bpf_redirect_map(&xsk_map, qid, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

