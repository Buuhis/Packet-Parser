#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} xsks_map SEC(".maps");

static __always_inline void inc_stat(int idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(0);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(1);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    int key0 = 0, key1 = 1;
    __u32 *network = bpf_map_lookup_elem(&config_map, &key0);
    __u32 *netmask = bpf_map_lookup_elem(&config_map, &key1);
    if (!network || !netmask) {
        inc_stat(4);
        return XDP_PASS;
    }

    if ((ip->daddr & *netmask) == *network) {
        inc_stat(2);
        return XDP_PASS;
    }

    inc_stat(3);

    int qid = ctx->rx_queue_index;
    int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
    if (!sock) {
        inc_stat(6);
        return XDP_PASS;
    }

    inc_stat(5);
    return bpf_redirect_map(&xsks_map, qid, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
