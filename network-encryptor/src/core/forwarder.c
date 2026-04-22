#include "../../inc/forwarder.h"
#include "../../inc/packet_crypto.h"
#include "../../inc/flow_table.h"
#include "../../inc/config.h"
#include "../../inc/crypto_layer2.h"
#include "../../inc/crypto_layer3.h"
#include "../../inc/crypto_layer4.h"
#include "../../inc/wan_arp.h"
#include "../../inc/crypto_policy_utils.h"
#include "../../inc/crypto_dispatch.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdatomic.h>


#define NUM_WORKERS 1
#define WORKER_RING_SIZE 4096

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;

static struct flow_table g_flow_table;


static struct packet_crypto_ctx g_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];
static int g_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static struct crypto_policy g_active_policies[MAX_CRYPTO_POLICIES];
static int g_active_policy_count = 0;
static struct packet_crypto_ctx g_prev_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_prev_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];
static int g_prev_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static struct crypto_policy g_prev_policies[MAX_CRYPTO_POLICIES];
static int g_prev_policy_count = 0;
static uint64_t g_prev_policy_grace_until_ms = 0;
#define POLICY_RELOAD_GRACE_MS 60000ULL
static uint64_t g_profile_hits[MAX_PROFILES];
static uint64_t g_profile_miss_hits;
static uint64_t g_profile_log_seq;


static struct app_config *g_cfg_ptr = NULL;
static atomic_int g_reload_pause = 0;
static atomic_int g_inflight_packets = 0;

static inline uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int packet_critical_enter(void) {
    for (;;) {
        while (atomic_load_explicit(&g_reload_pause, memory_order_acquire))
            sched_yield();
        atomic_fetch_add_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
        if (!atomic_load_explicit(&g_reload_pause, memory_order_acquire))
            return 1;
        atomic_fetch_sub_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
    }
}

static void packet_critical_leave(void) {
    atomic_fetch_sub_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static int prev_policy_grace_active(void) {
    if (g_prev_policy_count <= 0)
        return 0;
    uint64_t now = monotonic_ms();
    if (now == 0 || g_prev_policy_grace_until_ms == 0)
        return 0;
    return now <= g_prev_policy_grace_until_ms;
}

static int same_topology(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    for (int i = 0; i < a->local_count; i++) {
        if (strcmp(a->locals[i].ifname, b->locals[i].ifname) != 0)
            return 0;
    }
    for (int i = 0; i < a->wan_count; i++) {
        if (strcmp(a->wans[i].ifname, b->wans[i].ifname) != 0)
            return 0;
    }
    return 1;
}

static int same_crypto_policy(const struct crypto_policy *a, const struct crypto_policy *b) {
    if (!a || !b)
        return 0;
    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask &&
           a->crypto_mode == b->crypto_mode &&
           a->aes_bits == b->aes_bits &&
           a->nonce_size == b->nonce_size &&
           memcmp(a->key, b->key, AES_KEY_LEN) == 0;
}

static int crypto_runtime_changed(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 1;
    if (a->crypto_enabled != b->crypto_enabled ||
        a->encrypt_layer != b->encrypt_layer ||
        a->crypto_mode != b->crypto_mode ||
        a->aes_bits != b->aes_bits ||
        a->nonce_size != b->nonce_size ||
        a->fake_ethertype_ipv4 != b->fake_ethertype_ipv4 ||
        a->fake_ethertype_ipv6 != b->fake_ethertype_ipv6 ||
        a->fake_protocol != b->fake_protocol ||
        a->policy_count != b->policy_count) {
        return 1;
    }
    for (int i = 0; i < a->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        if (!same_crypto_policy(&a->policies[i], &b->policies[i]))
            return 1;
    }
    return 0;
}

static int forwarding_runtime_changed(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 1;
    if (a->profile_count != b->profile_count ||
        a->wan_count != b->wan_count ||
        a->local_count != b->local_count ||
        a->redirect.src_count != b->redirect.src_count ||
        a->redirect.dst_count != b->redirect.dst_count) {
        return 1;
    }
    for (uint32_t i = 0; i < a->redirect.src_count && i < MAX_SRC_NETS; i++) {
        if (a->redirect.src_net[i] != b->redirect.src_net[i] ||
            a->redirect.src_mask[i] != b->redirect.src_mask[i]) {
            return 1;
        }
    }
    for (uint32_t i = 0; i < a->redirect.dst_count && i < MAX_DST_NETS; i++) {
        if (a->redirect.dst_net[i] != b->redirect.dst_net[i] ||
            a->redirect.dst_mask[i] != b->redirect.dst_mask[i]) {
            return 1;
        }
    }
    return 0;
}

static int rebuild_crypto_runtime(const struct app_config *cfg, int *has_encrypt_l2_out) {
    int has_encrypt_l2 = 0;
    struct packet_crypto_ctx old_ctx[MAX_CRYPTO_POLICIES];
    int old_ready[MAX_CRYPTO_POLICIES];
    struct crypto_policy old_policies[MAX_CRYPTO_POLICIES];
    int old_policy_count = g_active_policy_count;
    if (old_policy_count > MAX_CRYPTO_POLICIES)
        old_policy_count = MAX_CRYPTO_POLICIES;
    memcpy(old_ctx, g_policy_crypto_ctx, sizeof(old_ctx));
    memcpy(old_ready, g_policy_crypto_ctx_ready, sizeof(old_ready));
    memcpy(old_policies, g_active_policies, sizeof(old_policies));

    memset(g_policy_crypto_ctx_ready, 0, sizeof(g_policy_crypto_ctx_ready));
    for (int a = 0; a <= POLICY_ACTION_ENCRYPT_L4; a++) {
        for (int id = 0; id < 256; id++)
            g_policy_index_by_action_id[a][id] = -1;
    }

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action == POLICY_ACTION_BYPASS)
            continue;
        int key_nonzero = 0;
        for (int k = 0; k < AES_KEY_LEN; k++) {
            if (cp->key[k] != 0) { key_nonzero = 1; break; }
        }
        if (!key_nonzero)
            continue;

        int reused = 0;
        for (int oi = 0; oi < old_policy_count; oi++) {
            if (!old_ready[oi])
                continue;
            if (!same_crypto_policy(&old_policies[oi], cp))
                continue;
            g_policy_crypto_ctx[pi] = old_ctx[oi];
            g_policy_crypto_ctx_ready[pi] = 1;
            reused = 1;
            break;
        }

        if (!reused) {
            packet_crypto_set_aes_bits(cp->aes_bits);
            if (packet_crypto_init(&g_policy_crypto_ctx[pi], cp->key) != 0) {
                fprintf(stderr, "[DB CRYPTO] Failed to init policy ctx id=%d (AES=%d)\n",
                        cp->id, cp->aes_bits);
                continue;
            }
            g_policy_crypto_ctx_ready[pi] = 1;
        }
        if (cp->action >= 0 && cp->action <= POLICY_ACTION_ENCRYPT_L4) {
            uint8_t pid = (uint8_t)cp->id;
            if (g_policy_index_by_action_id[cp->action][pid] < 0)
                g_policy_index_by_action_id[cp->action][pid] = pi;
        }
        if (cp->action == POLICY_ACTION_ENCRYPT_L2)
            has_encrypt_l2 = 1;
    }
    g_active_policy_count = cfg->policy_count;
    if (g_active_policy_count > MAX_CRYPTO_POLICIES)
        g_active_policy_count = MAX_CRYPTO_POLICIES;
    memcpy(g_active_policies, cfg->policies, sizeof(g_active_policies));
    if (has_encrypt_l2_out)
        *has_encrypt_l2_out = has_encrypt_l2;
    return 0;
}

static void compute_profile_weighted_wan_windows(const struct app_config *cfg,
                                                 uint32_t *out_wan_window_sizes,
                                                 int max_wans) {
    if (!cfg || !out_wan_window_sizes || max_wans <= 0)
        return;


    const uint32_t base_kb = WAN_REORDER_WINDOW_KB;
    const uint32_t base_bytes = base_kb * 1024U;


    const uint32_t min_kb = 512; 
    const uint32_t min_bytes = min_kb * 1024U;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled || p->wan_count <= 0)
            continue;

        int sumw = 0;
        for (int i = 0; i < p->wan_count; i++) {
            int w = p->wan_bandwidth_weight[i];
            if (w > 0)
                sumw += w;
        }
        if (sumw <= 0)
            continue; 

        for (int i = 0; i < p->wan_count; i++) {
            int wan_idx = p->wan_indices[i];
            int w = p->wan_bandwidth_weight[i];
            if (wan_idx < 0 || wan_idx >= max_wans)
                continue;
            if (w <= 0)
                continue;

            uint64_t scaled = ((uint64_t)base_bytes * (uint64_t)w) / (uint64_t)sumw;
            uint32_t win = (scaled > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)scaled;
            win = clamp_u32(win, min_bytes, base_bytes);
            out_wan_window_sizes[wan_idx] = win;
        }
    }
}

static int select_wan_idx_for_packet(struct forwarder *fwd,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t protocol, uint32_t pkt_len) {

    if (fwd && fwd->cfg && fwd->cfg->profile_count > 0) {
        int profile_idx = config_select_profile_for_flow(fwd->cfg, src_ip, dst_ip);
        if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
            struct profile_config *p = &fwd->cfg->profiles[profile_idx];
            if (p->wan_count > 1) {
                int allowed[MAX_INTERFACES];
                int weights[MAX_INTERFACES];
                int n = 0;
                int any_weight = 0;
                for (int i = 0; i < p->wan_count; i++) {
                    if (p->wan_bandwidth_weight[i] > 0)
                        any_weight = 1;
                }
                for (int i = 0; i < p->wan_count && n < MAX_INTERFACES; i++) {
                    int wi = p->wan_indices[i];
                    if (wi < 0 || wi >= fwd->cfg->wan_count)
                        continue;
                    allowed[n] = wi;
                    if (any_weight && p->wan_bandwidth_weight[i] <= 0)
                        continue;
                    weights[n] = p->wan_bandwidth_weight[i];
                    n++;
                }
                if (n == 1)
                    return allowed[0];
                if (n > 1) {
                    const int *wp = any_weight ? weights : NULL;
                    return flow_table_get_wan_profile(&g_flow_table,
                                                      src_ip, dst_ip,
                                                      src_port, dst_port,
                                                      protocol, pkt_len,
                                                      allowed, n, wp);
                }
            } else if (p->wan_count == 1) {
                int wi = p->wan_indices[0];
                if (wi >= 0 && wi < fwd->cfg->wan_count)
                    return wi;
            }
        }
    }

    return flow_table_get_wan(&g_flow_table,
                               src_ip, dst_ip, src_port, dst_port,
                               protocol, pkt_len);
}

static const struct crypto_policy *select_crypto_policy_for_packet(struct forwarder *fwd,
                                                                     uint32_t src_ip, uint32_t dst_ip,
                                                                     uint16_t src_port, uint16_t dst_port,
                                                                     uint8_t protocol) {
    if (!fwd || !fwd->cfg)
        return NULL;
    return crypto_select_policy_for_flow(fwd->cfg,
                                          src_ip, dst_ip,
                                          src_port, dst_port,
                                          protocol);
}

static void apply_default_crypto_params(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    crypto_apply_default_from_cfg(fwd->cfg);
}

static void apply_crypto_params_from_policy(const struct crypto_policy *cp) {
    if (!cp)
        return;
    crypto_apply_from_policy(cp);
}

static int encrypt_packet_with_ctx(struct packet_crypto_ctx *ctx,
                                     void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled || !ctx) return 0;
    int new_len = packet_encrypt(ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0)
        return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static struct arp_cache g_arp[MAX_INTERFACES];
static struct arp_cache g_wan_arp[MAX_INTERFACES];
static int g_arp_inited = 0;

static int set_wan_l2_addrs(struct forwarder *fwd, int wan_idx, uint8_t *pkt) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;
    return wan_rewrite_dest_mac(&g_wan_arp[wan_idx],
                                 &fwd->cfg->wans[wan_idx],
                                 &fwd->wans[wan_idx],
                                 pkt);
}

static void log_wan_peer_mac(struct forwarder *fwd, int wan_idx) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return;
    wan_log_peer_mac(&g_wan_arp[wan_idx], fwd->wans[wan_idx].ifname, &fwd->cfg->wans[wan_idx]);
}

struct packet_job {
    struct forwarder *fwd;
    int local_idx;
    int queue_idx;
    int tx_queue_base;
    void *pkt_ptr;
    uint32_t pkt_len;
    uint64_t addr;
};

struct worker_ring {
    struct packet_job jobs[WORKER_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    pthread_mutex_t lock;
} __attribute__((aligned(64)));

static struct worker_ring g_worker_rings[NUM_WORKERS];
static uint32_t g_dispatch_counter = 0;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int tx_queue_base;
    int core_id;
    int wan_worker_index;
    int worker_id;
};

static void pin_thread_to_core(int core_id) {
    (void)core_id;

    core_id = 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int decrypt_packet_auto_l2(struct forwarder *fwd,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;


    uint8_t pkt_marker = pkt[12];
    uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
    if (!((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
          (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)))) {
        return 0;
    }

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        int new_len = packet_decrypt(&crypto_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }


    uint8_t policy_id = pkt[13];
    int pi = g_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L2][policy_id];
    if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        apply_crypto_params_from_policy(cp);
        int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
        if (new_len < 0)
            return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    if (prev_policy_grace_active()) {
        int ppi = g_prev_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L2][policy_id];
        if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
            const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
            apply_crypto_params_from_policy(cp_prev);
            int new_len = packet_decrypt(&g_prev_policy_crypto_ctx[ppi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }
    }


    return -1;
}


static int l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len,
                                uint8_t *policy_id_out) {
    if (!pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;


    return crypto_l3_extract_policy_id(pkt, pkt_len, policy_id_out);
}

static int decrypt_packet_auto_by_action(struct forwarder *fwd,
                                           uint8_t *pkt, uint32_t *pkt_len,
                                           int action_layer,
                                           uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;

    struct crypto_dispatch_ctx dctx = {
        .base_ctx = &crypto_ctx,
        .per_policy_ctx = g_policy_crypto_ctx,
        .per_policy_ready = g_policy_crypto_ctx_ready,
        .policies = fwd->cfg ? fwd->cfg->policies : NULL,
        .policy_count = fwd->cfg ? fwd->cfg->policy_count : 0,
        .policy_index_by_action_id = g_policy_index_by_action_id,
        .prev_per_policy_ctx = g_prev_policy_crypto_ctx,
        .prev_per_policy_ready = g_prev_policy_crypto_ctx_ready,
        .prev_policies = g_prev_policies,
        .prev_policy_count = g_prev_policy_count,
        .prev_policy_index_by_action_id = g_prev_policy_index_by_action_id,
        .prev_grace_active = prev_policy_grace_active()
    };
    return crypto_decrypt_packet_auto_by_action(crypto_enabled, fwd->cfg, &dctx,
                                                action_layer, pkt, pkt_len,
                                                scratch, scratch_sz);
}


static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol) {
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    uint8_t *transport = pkt + l3_off + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct tcphdr)))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct udphdr)))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}

static inline uint32_t flow_hash_local_tq(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t src_port, uint16_t dst_port,
                                          uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

static void *gc_thread(void *arg) {
    (void)arg;
    pin_thread_to_core(0);
    while (running) {
        sleep(60); 
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}



static void *local_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint8_t protocol = 0;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_lens[i]) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *wan_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];

            uint32_t dest_ip = get_dest_ip(pkt, pkt_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            
            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(pkt, dst_mac, 6);
                memcpy(pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(wan, queue_idx, &addrs[i], 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used_queues[l]) {
                for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++) {
                    if (local_used_queues[l] & (1u << q))
                        interface_send_flush_queue(&fwd->locals[l], q);
                }
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *local_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint8_t protocol = 0;
            int flow_ok = 0;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                flow_ok = 1;
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];

            uint32_t pkt_len = pkt_lens[i];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            const struct crypto_policy *cp = NULL;
            if (flow_ok) {
                cp = select_crypto_policy_for_packet(fwd,
                                                     src_ip, dst_ip,
                                                     src_port, dst_port,
                                                     protocol);
            }
            struct packet_crypto_ctx *use_ctx = &crypto_ctx;
            int bypass_crypto = 0;
            int drop_unmatched = 0;

            if (cp) {
                if (cp->action == POLICY_ACTION_BYPASS) {
                    bypass_crypto = 1;
                } else if (cp->action != POLICY_ACTION_ENCRYPT_L2) {

                    bypass_crypto = 1;
                } else {
                    int pi = (int)(cp - fwd->cfg->policies);
                    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                        use_ctx = &g_policy_crypto_ctx[pi];
                    } else {
                        bypass_crypto = 1;
                    }
                    if (!bypass_crypto)
                        apply_crypto_params_from_policy(cp);
                }
            } else {
                drop_unmatched = (fwd->cfg && fwd->cfg->policy_count > 0) ? 1 : 0;
                bypass_crypto = !drop_unmatched;
            }

            if (drop_unmatched) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (bypass_crypto) {
                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                continue;
            }
            if (encrypt_packet_with_ctx(use_ctx, pkt_ptrs[i], &pkt_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *local_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();


        for (int i = 0; i < rcvd; i++) {
            struct packet_job job;
            job.fwd = fwd;
            job.local_idx = local_idx;
            job.queue_idx = queue_idx;
            job.tx_queue_base = tx_base;
            job.pkt_ptr = pkt_ptrs[i];
            job.pkt_len = pkt_lens[i];
            job.addr = addrs[i];

            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;
            uint32_t key_hash;
            if (parse_flow(job.pkt_ptr, job.pkt_len,
                           &src_ip, &dst_ip,
                           &src_port, &dst_port,
                           &protocol) == 0) {
                key_hash = flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol);
            } else {
                key_hash = __sync_fetch_and_add(&g_dispatch_counter, 1);
            }

            uint32_t target = key_hash % NUM_WORKERS;
            struct worker_ring *ring = &g_worker_rings[target];

            int enqueued = 0;
            pthread_mutex_lock(&ring->lock);
            uint32_t next_tail = (ring->tail + 1) % WORKER_RING_SIZE;
            if (next_tail != ring->head) {
                ring->jobs[ring->tail] = job;
                ring->tail = next_tail;
                enqueued = 1;
            }
            pthread_mutex_unlock(&ring->lock);

            if (!enqueued) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(local, queue_idx, &addrs[i], 1);
            }
        }
        packet_critical_leave();
    }

    return NULL;
}



static void *wan_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;


            if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                        decrypt_scratch, sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;


            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();

    }
    return NULL;
}



static void *wan_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            (void)0;

            if (crypto_enabled && crypto_layer == POLICY_ACTION_ENCRYPT_L3 &&
                fwd->cfg && fwd->cfg->policy_count > 0) {
                uint8_t policy_id = 0;
                int found = 0;
                if (l3_extract_policy_id(pkt, pkt_len, &policy_id) == 0) {
                    int pi = g_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L3][policy_id];
                    if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
                        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
                        apply_crypto_params_from_policy(cp);
                        found = 1;
                    }
                    if (!found && prev_policy_grace_active()) {
                        int ppi = g_prev_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L3][policy_id];
                        if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
                            const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
                            apply_crypto_params_from_policy(cp_prev);
                            found = 1;
                        }
                    }
                }
                if (!found)
                    apply_default_crypto_params(fwd);
            }


            {
                uint8_t pkt_marker = pkt[12];
                uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
                uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
                int has_l2_marker =
                    ((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
                     (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)));
                if (has_l2_marker) {
                    if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                               decrypt_scratch,
                                               sizeof(decrypt_scratch)) != 0) {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                }
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L3,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L4,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;


            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();

    }
    return NULL;
}

static void *worker_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    int worker_id = args->worker_id;

    if (worker_id < 0 || worker_id >= NUM_WORKERS)
        return NULL;

    pin_thread_to_core(args->core_id);

    struct worker_ring *ring = &g_worker_rings[worker_id];

    while (running) {
        struct packet_job job;
        int has_job = 0;

        pthread_mutex_lock(&ring->lock);
        if (ring->head != ring->tail) {
            job = ring->jobs[ring->head];
            ring->head = (ring->head + 1) % WORKER_RING_SIZE;
            has_job = 1;
        }
        pthread_mutex_unlock(&ring->lock);

        if (!has_job) {
            sched_yield();
            continue;
        }
        packet_critical_enter();

        struct forwarder *fwd = job.fwd;
        if (!fwd) {
            continue;
        }

        uint32_t wan_tx_q[MAX_INTERFACES];
        int wan_used[MAX_INTERFACES] = {0};
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = job.tx_queue_base % fwd->wans[w].queue_count;

        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;

        int flow_ok = (parse_flow(job.pkt_ptr, job.pkt_len,
                                  &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0);
        int profile_idx = -1;
        if (flow_ok && fwd->cfg) {
            profile_idx = config_select_profile_for_flow(fwd->cfg, src_ip, dst_ip);
            if (profile_idx >= 0 && profile_idx < MAX_PROFILES)
                __sync_fetch_and_add(&g_profile_hits[profile_idx], 1);
            else
                __sync_fetch_and_add(&g_profile_miss_hits, 1);
        }

        int wan_idx;
        if (flow_ok) {
            wan_idx = select_wan_idx_for_packet(fwd,
                                                src_ip, dst_ip, src_port, dst_port,
                                                protocol, job.pkt_len);
        } else {
            wan_idx = 0;
        }

        if (wan_idx < 0 || wan_idx >= fwd->wan_count) {
            wan_idx = 0;
        }

        uint64_t seq = __sync_add_and_fetch(&g_profile_log_seq, 1);
        if ((seq % 20000ULL) == 0 && fwd->cfg) {
            fprintf(stderr, "[PROFILE HIT] total=%llu miss=%llu",
                    (unsigned long long)seq,
                    (unsigned long long)g_profile_miss_hits);
            for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
                fprintf(stderr, " p%d(%s)=%llu",
                        pi, fwd->cfg->profiles[pi].name,
                        (unsigned long long)g_profile_hits[pi]);
            }
            fprintf(stderr, " last_sel=%d last_wan=%d\n", profile_idx, wan_idx);
        }

        struct xsk_interface *wan = &fwd->wans[wan_idx];
        int tq = wan_tx_q[wan_idx];

        uint32_t pkt_len = job.pkt_len;


        const struct crypto_policy *cp = NULL;
        struct packet_crypto_ctx *use_ctx = &crypto_ctx;
        int bypass_crypto = 0;
        if (crypto_enabled) {
            if (!flow_ok) {
                bypass_crypto = 1;
            } else {
                cp = select_crypto_policy_for_packet(fwd,
                                                     src_ip, dst_ip,
                                                     src_port, dst_port,
                                                     protocol);
                if (cp) {
                    if (cp->action == POLICY_ACTION_BYPASS) {
                        bypass_crypto = 1;
                    } else {
                        int pi = (int)(cp - fwd->cfg->policies);
                        if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                            use_ctx = &g_policy_crypto_ctx[pi];
                        } else {
                            bypass_crypto = 1;
                        }
                        if (!bypass_crypto)
                            apply_crypto_params_from_policy(cp);
                    }
                } else {
                    if (fwd->cfg && fwd->cfg->policy_count > 0) {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        goto release_local;
                    }
                    bypass_crypto = 1;
                }
            }

            if (bypass_crypto) {
                uint8_t *pkt = (uint8_t *)job.pkt_ptr;
                if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    goto release_local;
                }

                if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                goto skip_encrypt_flush;
            }
        }

        if (!crypto_enabled) {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        } else {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            int new_len = -1;
            if (cp) {
                if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
                    new_len = crypto_layer2_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L3) {
                    new_len = crypto_layer3_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L4) {
                    new_len = crypto_layer4_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                }
            }

            if (new_len < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }
            pkt_len = (uint32_t)new_len;

            if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

skip_encrypt_flush:
        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

release_local:
        if (job.fwd && job.local_idx >= 0 &&
            job.local_idx < job.fwd->local_count) {
            struct xsk_interface *local = &job.fwd->locals[job.local_idx];
            interface_recv_release_single_queue(local, job.queue_idx, &job.addr, 1);
        }
        packet_critical_leave();
    }

    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    g_cfg_ptr = cfg;
    interface_reset_redirect_maps();


    for (int i = 0; i < cfg->local_count; i++)
        cfg->locals[i].queue_count = 1;
    for (int i = 0; i < cfg->wan_count; i++)
        cfg->wans[i].queue_count = 1;

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    int has_encrypt_l2 = 0;
    if (crypto_enabled) {
        if (g_active_policy_count > 0) {
            memcpy(g_prev_policy_crypto_ctx, g_policy_crypto_ctx, sizeof(g_prev_policy_crypto_ctx));
            memcpy(g_prev_policy_crypto_ctx_ready, g_policy_crypto_ctx_ready, sizeof(g_prev_policy_crypto_ctx_ready));
            memcpy(g_prev_policy_index_by_action_id, g_policy_index_by_action_id, sizeof(g_prev_policy_index_by_action_id));
            memcpy(g_prev_policies, g_active_policies, sizeof(g_prev_policies));
            g_prev_policy_count = g_active_policy_count;
            g_prev_policy_grace_until_ms = monotonic_ms() + POLICY_RELOAD_GRACE_MS;
            fprintf(stderr, "[CRYPTO] policy grace window active for %llu ms\n",
                    (unsigned long long)POLICY_RELOAD_GRACE_MS);
        } else {
            memset(g_prev_policy_crypto_ctx_ready, 0, sizeof(g_prev_policy_crypto_ctx_ready));
            for (int a = 0; a <= POLICY_ACTION_ENCRYPT_L4; a++) {
                for (int id = 0; id < 256; id++)
                    g_prev_policy_index_by_action_id[a][id] = -1;
            }
            g_prev_policy_count = 0;
            g_prev_policy_grace_until_ms = 0;
        }

        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to initialize AES-%d encryption\n", cfg->aes_bits);
            return -1;
        }


        rebuild_crypto_runtime(cfg, &has_encrypt_l2);

        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2) {
            if (cfg->fake_ethertype_ipv4 == 0 && cfg->fake_ethertype_ipv6 == 0) {

                cfg->fake_ethertype_ipv4 = 0x88b5;
                cfg->fake_ethertype_ipv6 = 0x88b6;
            }
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        }
        if (crypto_layer == 3) {
            if (cfg->fake_protocol != 0)
                packet_crypto_set_fake_protocol(cfg->fake_protocol);
            else
                packet_crypto_set_fake_protocol(99);
        }

    } else {
        g_active_policy_count = 0;
    }



    uint32_t wan_window_sizes[MAX_INTERFACES] = {0};
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        wan_window_sizes[i] = cfg->wans[i].window_size;
    compute_profile_weighted_wan_windows(cfg, wan_window_sizes, cfg->wan_count);
    flow_table_init(&g_flow_table, wan_window_sizes, cfg->wan_count);

    int total_threads = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
        total_threads += cfg->locals[i].queue_count;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);
        total_threads += cfg->wans[i].queue_count;
    }
    total_threads += NUM_WORKERS;

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            interface_cleanup(&fwd->locals[i]);
            goto err_locals;
        }
        fwd->local_count++;
    }


    if (cfg->redirect.src_count > 0 || cfg->redirect.dst_count > 0) {
        if (interface_push_redirect_cfg(&cfg->redirect) != 0) {
            fprintf(stderr, "[XDP] Failed to push redirect rules to config_map\n");

        }
    }

    
    for (int i = 0; i < fwd->local_count; i++) {
        if (arp_init_for_local(&g_arp[i], &fwd->locals[i], &running) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            fprintf(stderr, "[ARP] ready on %s (ip=%u)\n",
                    g_arp[i].ifname, (unsigned)ntohl(g_arp[i].if_ip));
        } else {
            fprintf(stderr, "[ARP] WARN: cannot init local ARP on %s\n",
                    fwd->locals[i].ifname);
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t wan_fake4 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv4 : 0;
        uint16_t wan_fake6 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv6 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o", wan_fake4, wan_fake6) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
        if (cfg->wans[i].dst_ip != 0) {

            memset(fwd->wans[i].dst_mac, 0, MAC_LEN);
            memset(fwd->wans[i].src_mac, 0, MAC_LEN);
        }
    }


    for (int i = 0; i < fwd->wan_count; i++) {
        if (cfg->wans[i].dst_ip == 0) {
            fprintf(stderr,
                    "[WAN ARP] if=%s dst_ip=0 -> using static/fallback MAC path\n",
                    cfg->wans[i].ifname);
            continue;
        }
        if (arp_init_for_local(&g_wan_arp[i], &fwd->wans[i], &running) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_wan_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            log_wan_peer_mac(fwd, i);
        } else {
            fprintf(stderr, "[ARP] WARN: cannot init WAN ARP on %s\n", cfg->wans[i].ifname);
        }
    }

    return 0;

err_wans:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
err_locals:
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    return -1;
}

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg) {
    if (!fwd || !cfg || !fwd->cfg)
        return -1;
    if (!same_topology(fwd->cfg, cfg)) {
        fprintf(stderr, "[RELOAD] topology changed; hot reload rejected\n");
        return -1;
    }
    int need_crypto_reload = crypto_runtime_changed(fwd->cfg, cfg);
    int need_forwarding_reload = forwarding_runtime_changed(fwd->cfg, cfg);
    if (!need_crypto_reload && !need_forwarding_reload) {
        fwd->cfg = cfg;
        g_cfg_ptr = cfg;
        fprintf(stderr, "[RELOAD] skipped: config is unchanged\n");
        return 0;
    }

    atomic_store_explicit(&g_reload_pause, 1, memory_order_release);
    while (atomic_load_explicit(&g_inflight_packets, memory_order_acquire) > 0)
        sched_yield();

    fwd->cfg = cfg;
    g_cfg_ptr = cfg;
    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    if (crypto_enabled && need_crypto_reload) {
        int has_encrypt_l2 = 0;
        rebuild_crypto_runtime(cfg, &has_encrypt_l2);
        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2)
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        if (cfg->encrypt_layer == 3)
            packet_crypto_set_fake_protocol(cfg->fake_protocol ? cfg->fake_protocol : 99);
    }

    atomic_store_explicit(&g_reload_pause, 0, memory_order_release);
    fprintf(stderr, "[RELOAD] hot reload applied in-place (crypto=%s, forwarding=%s)\n",
            need_crypto_reload ? "yes" : "no",
            need_forwarding_reload ? "yes" : "no");
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd) {
    if (crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    flow_table_cleanup(&g_flow_table);

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}


static void forwarder_run_no_crypto(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[NO-CRYPTO] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_no_crypto, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_no_crypto, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l2(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;


    fprintf(stderr, "[L2 DEBUG] total_local_queues=%d, total_wan_queues=%d\n",
            total_local_queues, total_wan_queues);
    for (int i = 0; i < fwd->local_count; i++) {
        fprintf(stderr, "[L2 DEBUG] local[%d] ifname=%s queue_count=%d\n",
                i, fwd->locals[i].ifname, fwd->locals[i].queue_count);
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        fprintf(stderr, "[L2 DEBUG] wan[%d] ifname=%s queue_count=%d\n",
                i, fwd->wans[i].ifname, fwd->wans[i].queue_count);
    }


    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L2] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l2, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l2, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l3(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L3] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 0;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l4(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L4] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 0;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}



void forwarder_run(struct forwarder *fwd) {
    running = 1;
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!crypto_enabled) {
        forwarder_run_no_crypto(fwd);
    } else if (crypto_layer == 2) {
        forwarder_run_l2(fwd);
    } else if (crypto_layer == 3) {
        forwarder_run_l3(fwd);
    } else if (crypto_layer == 4) {
        forwarder_run_l4(fwd);
    } else {
        forwarder_run_l3(fwd);
    }
}

void forwarder_stop(void) {
    running = 0;
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;

    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES)
             ? fwd->locals[0].queue_count : 0;
    if (nq <= 0) nq = 1;

    uint64_t tx_wait_loops = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait_loops += fwd->locals[i].queues[q].tx_wait_loops;
    }

    fprintf(stdout,
            "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu "
            "dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu",
            fwd->local_to_wan,
            fwd->wan_to_local,
            fwd->total_dropped,
            fwd->dropped_bad_ip,
            fwd->dropped_no_local_match,
            fwd->dropped_local_tx_fail);
    for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
        fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait_loops);

    for (int w = 0; w < fwd->wan_count; w++) {
        const struct wan_config *wc = &fwd->cfg->wans[w];
        if (wc->dst_ip == 0) {
            fprintf(stdout, "[WAN ARP] if=%s peer ARP=disabled (static/fallback path)\n",
                    fwd->wans[w].ifname);
            continue;
        }

        char ipbuf[INET_ADDRSTRLEN] = {0};
        struct in_addr a = { .s_addr = wc->dst_ip };
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));

        uint8_t mac[6];
        if (arp_cache_lookup(&g_wan_arp[w], wc->dst_ip, mac)) {
            fprintf(stdout,
                    "[WAN ARP] if=%s peer=%s dest_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    fwd->wans[w].ifname, ipbuf,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            fprintf(stdout, "[WAN ARP] if=%s peer=%s dest_mac=UNRESOLVED\n",
                    fwd->wans[w].ifname, ipbuf);
        }
    }
}