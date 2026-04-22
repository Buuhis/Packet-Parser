#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_SRC_NETS 32
#define MAX_DST_NETS 32
#define IPPROTO_ICMP_VAL 1
#define ETH_P_ARP_VAL 0x0806

struct redirect_cfg {
    __u32 src_net[MAX_SRC_NETS];
    __u32 src_mask[MAX_SRC_NETS];
    __u32 src_count;

    __u32 dst_net[MAX_DST_NETS];
    __u32 dst_mask[MAX_DST_NETS];
    __u32 dst_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct redirect_cfg);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      __u32 *src_ip, __u32 *dst_ip, __u8 *proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    if (proto)
        *proto = ip->protocol;
    return 0;
}

static __always_inline int ip_in_net(__u32 ip, __u32 net, __u32 mask)
{
    return (ip & mask) == (net & mask);
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    inc_stat(0);

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL)) {
        inc_stat(7);
        return XDP_PASS;
    }

    __u32 src_ip, dst_ip;
    __u8 l4_proto = 0;
    if (parse_ipv4(data, data_end, &src_ip, &dst_ip, &l4_proto) < 0) {
        inc_stat(1);
        return XDP_PASS;
    }


    if (l4_proto == IPPROTO_ICMP_VAL) {
        inc_stat(4);
        return XDP_PASS;
    }


    __u32 cfg_key = 0;
    struct redirect_cfg *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg) {
        inc_stat(2);
        return XDP_PASS;
    }

    int src_ok = (cfg->src_count == 0);
    int dst_ok = (cfg->dst_count == 0);

    for (int i = 0; i < MAX_SRC_NETS; i++) {
        if ((__u32)i < cfg->src_count &&
            ip_in_net(src_ip, cfg->src_net[i], cfg->src_mask[i])) {
            src_ok = 1;
            break;
        }
    }

    for (int i = 0; i < MAX_DST_NETS; i++) {
        if ((__u32)i < cfg->dst_count &&
            ip_in_net(dst_ip, cfg->dst_net[i], cfg->dst_mask[i])) {
            dst_ok = 1;
            break;
        }
    }

    if (!(src_ok && dst_ok)) {
        inc_stat(3);
        return XDP_PASS;
    }


    __u32 qid = 0;
    int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
    if (!sock) {
        inc_stat(5);
        return XDP_PASS;
    }

    inc_stat(6);
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";