#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PQC_HS_PORT      7090
#define IPPROTO_UDP_VAL  17

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, __u64);
} wan_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u16);
} wan_config_map SEC(".maps");

struct pqc_frag_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 ip_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pqc_frag_key);
    __type(value, __u8);
} pqc_frag_map SEC(".maps");

#define STAT_TOTAL      0
#define STAT_NON_IP     1
#define STAT_REDIRECT   2
#define STAT_NO_SOCK    3
#define STAT_ARP_PASS   4
#define STAT_ICMP_PASS  5
#define STAT_PQC_PASS   6
#define IPPROTO_ICMP_VAL 1

static __always_inline void inc_stat(int idx)
{
    __u64 *val = bpf_map_lookup_elem(&wan_stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;


    if (proto == __constant_htons(ETH_P_ARP)) {
        inc_stat(STAT_ARP_PASS);
        return XDP_PASS;
    }

    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Extract fragment offset and flags
        __u16 frag_off = bpf_ntohs(ip->frag_off);
        __u16 offset = frag_off & 0x1FFF;
        __u16 mf = frag_off & 0x2000;

        struct pqc_frag_key key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .ip_id = ip->id
        };

        // 1. Pass PQC subsequent fragments to the kernel
        if (offset > 0) {
            __u8 *val = bpf_map_lookup_elem(&pqc_frag_map, &key);
            if (val) {
                return XDP_PASS;
            }
        }

        if (ip->protocol == IPPROTO_ICMP_VAL) {
            inc_stat(STAT_ICMP_PASS);
            return XDP_PASS;
        }

        // 2. Pass PQC Handshake first fragment or unfragmented packets to the kernel
        if (ip->protocol == IPPROTO_UDP_VAL) {
            struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
            if ((void *)(udp + 1) <= data_end) {
                if (udp->dest == __constant_htons(PQC_HS_PORT) || udp->source == __constant_htons(PQC_HS_PORT)) {
                    if (mf) {
                        __u8 val = 1;
                        bpf_map_update_elem(&pqc_frag_map, &key, &val, BPF_ANY);
                    }
                    inc_stat(STAT_PQC_PASS);
                    return XDP_PASS;
                }
            }
        }

        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_IPV6))
        goto redirect;


    int key0 = 0, key1 = 1;
    __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
    if (fake4 && *fake4 != 0 &&
        (proto & __constant_htons(0xFF00)) == (*fake4 & __constant_htons(0xFF00)))
        goto redirect;

    __u16 *fake6 = bpf_map_lookup_elem(&wan_config_map, &key1);
    if (fake6 && *fake6 != 0 &&
        (proto & __constant_htons(0xFF00)) == (*fake6 & __constant_htons(0xFF00)))
        goto redirect;

    inc_stat(STAT_NON_IP);
    return XDP_PASS;

redirect:
    ;

    int queue_id = 0;
    int ret = bpf_redirect_map(&wan_xsks_map, queue_id, XDP_PASS);

    if (ret == XDP_REDIRECT) {
        inc_stat(STAT_REDIRECT);
    } else {
        inc_stat(STAT_NO_SOCK);
    }

    return ret;
}

char _license[] SEC("license") = "GPL";