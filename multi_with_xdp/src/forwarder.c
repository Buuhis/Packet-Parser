#include "../inc/forwarder.h"
#include "../inc/flow_table.h"
#include "../inc/fragment.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

static volatile int running = 1;

static struct flow_table g_flow_table;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int cpu_id;
    int tx_queue_base;
};

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static void pin_thread_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
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
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return -1;

    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    uint8_t *transport = (uint8_t *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr))
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

static void *gc_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(10);
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}

static void *local_queue_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int cpu_id = args->cpu_id;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    pin_thread_to_cpu(cpu_id);
    printf("[THREAD] LOCAL[%d] queue[%d] → CPU %d (tx_base=%d)\n",
           local_idx, queue_idx, cpu_id, tx_base);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    uint8_t frag1_buf[2048];
    uint8_t frag2_buf[2048];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = flow_table_get_wan(&g_flow_table,
                                              src_ip, dst_ip, src_port, dst_port,
                                              protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];

            if (frag_need_split(pkt_lens[i])) {
                uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

                uint32_t f1_len = 0, f2_len = 0;
                if (frag_split(pkt, pkt_lens[i],
                               frag1_buf, &f1_len,
                               frag2_buf, &f2_len) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                uint32_t wire_total = f1_len + f2_len;
                if (wire_total > pkt_lens[i]) {
                    flow_table_add_bytes(&g_flow_table,
                                         src_ip, dst_ip, src_port, dst_port,
                                         protocol, wire_total - pkt_lens[i]);
                }

                if (interface_send_batch_queue(wan, tq, frag1_buf, f1_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }

                if (interface_send_batch_queue(wan, tq, frag2_buf, f2_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }

            } else {
                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_lens[i]) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *wan_queue_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int cpu_id = args->cpu_id;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    pin_thread_to_cpu(cpu_id);
    printf("[THREAD] WAN[%d] queue[%d] → CPU %d (tx_base=%d)\n",
           wan_idx, queue_idx, cpu_id, tx_base);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    struct frag_table *frag_tbl = calloc(1, sizeof(struct frag_table));
    if (frag_tbl) {
        frag_table_init(frag_tbl);
    }

    uint8_t reassemble_buf[4096];

    int gc_counter = 0;

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int local_used[MAX_INTERFACES] = {0};
        int local_tx_q[MAX_INTERFACES];
        for (int l = 0; l < fwd->local_count; l++)
            local_tx_q[l] = tx_base % fwd->locals[l].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            uint16_t frag_pkt_id;
            uint8_t frag_index;
            int is_frag = 0;

            if (frag_tbl) {
                is_frag = frag_is_fragment(pkt, pkt_len, &frag_pkt_id, &frag_index);
            }

            if (is_frag) {
                int dec_len = frag_defragment(pkt, pkt_len,
                                               &frag_pkt_id, &frag_index);
                if (dec_len < 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
                pkt_len = (uint32_t)dec_len;

                uint32_t reasm_len = 0;
                int ret = frag_try_reassemble(frag_tbl, pkt, pkt_len,
                                               frag_pkt_id, frag_index,
                                               reassemble_buf, &reasm_len);
                if (ret == 0) {
                    continue;
                } else if (ret == 1) {
                    final_pkt = reassemble_buf;
                    final_len = reasm_len;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            }

            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config *local_cfg = &fwd->cfg->locals[local_idx];
            int tq = local_tx_q[local_idx];

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg,
                                                     final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used[local_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used[l])
                interface_send_to_local_flush_queue(&fwd->locals[l], local_tx_q[l]);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);

        if (frag_tbl && ++gc_counter >= 1000) {
            frag_table_gc(frag_tbl);
            gc_counter = 0;
        }
    }

    if (frag_tbl) free(frag_tbl);
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;

    uint32_t window_size = cfg->wans[0].window_size;
    flow_table_init(&g_flow_table, window_size, cfg->wan_count);
    printf("Flow table initialized: window_size=%u bytes, wan_count=%d\n",
           window_size, cfg->wan_count);

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 2) num_cpus = 2;

    int local_total = num_cpus / 2;
    int wan_total = num_cpus - local_total;

    int local_queues_each = (cfg->local_count > 0) ?
                            (local_total / cfg->local_count) : 1;
    if (local_queues_each < 1) local_queues_each = 1;

    int wan_queues_each = (cfg->wan_count > 0) ?
                          (wan_total / cfg->wan_count) : 1;
    if (wan_queues_each < 1) wan_queues_each = 1;

    int remainder = num_cpus - (local_queues_each * cfg->local_count)
                             - (wan_queues_each * cfg->wan_count);
    local_queues_each += (cfg->local_count > 0) ?
                         (remainder / cfg->local_count) : 0;

    printf("\n[CPU] ═══════════════════════════════════════════════\n");
    printf("[CPU] Detected %d CPU cores\n", num_cpus);
    printf("[CPU] Distribution: LOCAL=%d queues/iface x %d = %d threads\n",
           local_queues_each, cfg->local_count,
           local_queues_each * cfg->local_count);
    printf("[CPU]               WAN=%d queues/iface x %d = %d threads\n",
           wan_queues_each, cfg->wan_count,
           wan_queues_each * cfg->wan_count);
    printf("[CPU] Total: %d threads on %d cores\n",
           local_queues_each * cfg->local_count + wan_queues_each * cfg->wan_count,
           num_cpus);

    for (int i = 0; i < cfg->local_count; i++) {
        interface_set_queue_count(cfg->locals[i].ifname, local_queues_each);
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        interface_set_queue_count(cfg->wans[i].ifname, wan_queues_each);
    }
    printf("[CPU] ═══════════════════════════════════════════════\n\n");

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err_locals;
        }
        fwd->local_count++;
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o") != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
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

void forwarder_cleanup(struct forwarder *fwd) {
    flow_table_cleanup(&g_flow_table);

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues;

    printf("\n[THREAD] ═══════════════════════════════════════════\n");
    printf("[THREAD] CPUs available: %d\n", num_cpus);
    printf("[THREAD] LOCAL queues: %d, WAN queues: %d, total threads: %d\n",
           total_local_queues, total_wan_queues, total_threads);
    printf("[THREAD] Fragmentation: packets > %d bytes will be split\n",
           FRAG_MTU - FRAG_PLAIN_HDR_SIZE);

    if (total_threads > num_cpus) {
        printf("[THREAD] WARNING: %d threads > %d CPUs, some cores will be shared\n",
               total_threads, num_cpus);
    }

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "Failed to allocate thread arrays\n");
        free(threads);
        free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int cpu = 0;
    int thread_idx = 0;

    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].cpu_id = cpu % num_cpus;
            args[thread_idx].tx_queue_base = q;

            pthread_create(&threads[thread_idx], NULL, local_queue_thread, &args[thread_idx]);
            cpu++;
            thread_idx++;
        }
    }

    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].cpu_id = cpu % num_cpus;
            args[thread_idx].tx_queue_base = q;

            pthread_create(&threads[thread_idx], NULL, wan_queue_thread, &args[thread_idx]);
            cpu++;
            thread_idx++;
        }
    }

    printf("[THREAD] ═══════════════════════════════════════════\n\n");

    while (running) {
        sleep(1);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}

void forwarder_print_stats(struct forwarder *fwd) {
    (void)fwd;
}
