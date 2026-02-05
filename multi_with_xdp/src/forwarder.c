#include "../inc/forwarder.h"
#include "../inc/flow_table.h"
#include "../inc/fragment.h"
#include "../inc/pipeline.h"
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

/* ================================================================
 * Thread argument structs
 * ================================================================ */

struct rx_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int cpu_id;
};

struct worker_thread_args {
    struct forwarder *fwd;
    int worker_id;
    int cpu_id;
};

struct tx_thread_args {
    struct forwarder *fwd;
    int cpu_id;
};

/* ================================================================
 * Helpers
 * ================================================================ */

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

static uint32_t get_dest_ip(const uint8_t *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static int parse_flow(const uint8_t *pkt_data, uint32_t pkt_len,
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

/* ================================================================
 * Stage 1: RX Threads (lightweight - recv + hash + enqueue)
 * ================================================================ */

static void *rx_local_thread(void *arg) {
    struct rx_thread_args *a = (struct rx_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;
    int local_idx = a->iface_idx;
    int queue_idx = a->queue_idx;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    pin_thread_to_cpu(a->cpu_id);
    printf("[RX-LOCAL] iface[%d] queue[%d] -> CPU %d\n",
           local_idx, queue_idx, a->cpu_id);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0) continue;

        for (int i = 0; i < rcvd; i++) {
            int slot = pkt_pool_alloc(&pl->pool);
            if (slot < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            struct pkt_slot *ps = &pl->pool.slots[slot];
            uint32_t len = pkt_lens[i];
            if (len > PKT_SLOT_DATA_SIZE) len = PKT_SLOT_DATA_SIZE;
            memcpy(ps->data, pkt_ptrs[i], len);
            ps->len = len;

            uint32_t h = hash_5tuple(ps->data, len);
            int worker_id = h % pl->num_outbound_workers;

            if (mpmc_ring_enqueue(&pl->outbound_worker_rings[worker_id], (uint32_t)slot) != 0) {
                pkt_pool_free(&pl->pool, (uint32_t)slot);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *rx_wan_thread(void *arg) {
    struct rx_thread_args *a = (struct rx_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;
    int wan_idx = a->iface_idx;
    int queue_idx = a->queue_idx;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    pin_thread_to_cpu(a->cpu_id);
    printf("[RX-WAN] iface[%d] queue[%d] -> CPU %d\n",
           wan_idx, queue_idx, a->cpu_id);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0) continue;

        for (int i = 0; i < rcvd; i++) {
            int slot = pkt_pool_alloc(&pl->pool);
            if (slot < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            struct pkt_slot *ps = &pl->pool.slots[slot];
            uint32_t len = pkt_lens[i];
            if (len > PKT_SLOT_DATA_SIZE) len = PKT_SLOT_DATA_SIZE;
            memcpy(ps->data, pkt_ptrs[i], len);
            ps->len = len;

            /* Use IP pair hash so both fragments of same pkt go to same worker */
            uint32_t h = hash_ip_pair(ps->data, len);
            int worker_id = h % pl->num_inbound_workers;

            if (mpmc_ring_enqueue(&pl->inbound_worker_rings[worker_id], (uint32_t)slot) != 0) {
                pkt_pool_free(&pl->pool, (uint32_t)slot);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
    }

    return NULL;
}

/* ================================================================
 * Stage 2: Worker Threads (heavy processing)
 * ================================================================ */

static void *outbound_worker_thread(void *arg) {
    struct worker_thread_args *a = (struct worker_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;
    int my_id = a->worker_id;

    pin_thread_to_cpu(a->cpu_id);
    printf("[WORKER-OUT] id=%d -> CPU %d\n", my_id, a->cpu_id);

    uint32_t batch[64];

    while (running) {
        int count = mpmc_ring_dequeue_batch(
            &pl->outbound_worker_rings[my_id], batch, 64);

        if (count == 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < count; i++) {
            struct pkt_slot *pkt = &pl->pool.slots[batch[i]];

            /* ===== PACKET EDITING HERE ===== */
            /* (placeholder for future heavy processing) */
            /* ================================ */

            /* Classify: choose WAN */
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            if (parse_flow(pkt->data, pkt->len,
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                pkt->wan_idx = flow_table_get_wan(&g_flow_table,
                                                   src_ip, dst_ip, src_port, dst_port,
                                                   protocol, pkt->len);
            } else {
                pkt->wan_idx = 0;
            }

            /* Fragment if needed */
            if (frag_need_split(pkt->len)) {
                int slot2 = pkt_pool_alloc(&pl->pool);
                if (slot2 < 0) {
                    pkt_pool_free(&pl->pool, batch[i]);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                struct pkt_slot *pkt2 = &pl->pool.slots[slot2];
                uint32_t f1_len = 0, f2_len = 0;

                if (frag_split(pkt->data, pkt->len,
                               pkt->data, &f1_len,
                               pkt2->data, &f2_len) != 0) {
                    pkt_pool_free(&pl->pool, batch[i]);
                    pkt_pool_free(&pl->pool, (uint32_t)slot2);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                pkt->len = f1_len;
                pkt2->len = f2_len;
                pkt2->wan_idx = pkt->wan_idx;

                /* Account wire overhead for flow table */
                uint32_t wire_total = f1_len + f2_len;
                if (wire_total > pkt->len + pkt2->len) {
                    flow_table_add_bytes(&g_flow_table,
                                         src_ip, dst_ip, src_port, dst_port,
                                         protocol, wire_total - pkt->len);
                }

                /* Enqueue both fragments to TX */
                if (mpmc_ring_enqueue(&pl->tx_wan_rings[pkt->wan_idx], batch[i]) != 0) {
                    pkt_pool_free(&pl->pool, batch[i]);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                } else {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                }

                if (mpmc_ring_enqueue(&pl->tx_wan_rings[pkt2->wan_idx], (uint32_t)slot2) != 0) {
                    pkt_pool_free(&pl->pool, (uint32_t)slot2);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                } else {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                }
            } else {
                /* No fragmentation needed */
                if (mpmc_ring_enqueue(&pl->tx_wan_rings[pkt->wan_idx], batch[i]) != 0) {
                    pkt_pool_free(&pl->pool, batch[i]);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                } else {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                }
            }
        }
    }

    return NULL;
}

static void *inbound_worker_thread(void *arg) {
    struct worker_thread_args *a = (struct worker_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;
    int my_id = a->worker_id;

    pin_thread_to_cpu(a->cpu_id);
    printf("[WORKER-IN] id=%d -> CPU %d\n", my_id, a->cpu_id);

    /* Each inbound worker has its own frag table */
    struct frag_table *frag_tbl = calloc(1, sizeof(struct frag_table));
    if (frag_tbl)
        frag_table_init(frag_tbl);

    uint8_t reassemble_buf[4096];
    uint32_t batch[64];
    int gc_counter = 0;

    while (running) {
        int count = mpmc_ring_dequeue_batch(
            &pl->inbound_worker_rings[my_id], batch, 64);

        if (count == 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < count; i++) {
            struct pkt_slot *pkt = &pl->pool.slots[batch[i]];

            uint16_t frag_pkt_id;
            uint8_t frag_index;
            int is_frag = 0;

            if (frag_tbl)
                is_frag = frag_is_fragment(pkt->data, pkt->len,
                                            &frag_pkt_id, &frag_index);

            uint8_t *final_data = pkt->data;
            uint32_t final_len = pkt->len;
            int need_reassemble_copy = 0;

            if (is_frag) {
                int dec_len = frag_defragment(pkt->data, pkt->len,
                                               &frag_pkt_id, &frag_index);
                if (dec_len < 0) {
                    pkt_pool_free(&pl->pool, batch[i]);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                uint32_t reasm_len = 0;
                int ret = frag_try_reassemble(frag_tbl,
                                               pkt->data, (uint32_t)dec_len,
                                               frag_pkt_id, frag_index,
                                               reassemble_buf, &reasm_len);
                if (ret == 0) {
                    /* First fragment stored, waiting for second */
                    pkt_pool_free(&pl->pool, batch[i]);
                    continue;
                } else if (ret == 1) {
                    /* Reassembly complete */
                    final_data = reassemble_buf;
                    final_len = reasm_len;
                    need_reassemble_copy = 1;
                } else {
                    pkt_pool_free(&pl->pool, batch[i]);
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            }

            /* ===== PACKET EDITING HERE ===== */
            /* (placeholder for future heavy processing) */
            /* ================================ */

            /* Find destination LOCAL interface */
            uint32_t dest_ip = get_dest_ip(final_data, final_len);
            if (dest_ip == 0) {
                pkt_pool_free(&pl->pool, batch[i]);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                pkt_pool_free(&pl->pool, batch[i]);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            /* If reassembled, copy back into slot */
            if (need_reassemble_copy) {
                if (final_len > PKT_SLOT_DATA_SIZE) final_len = PKT_SLOT_DATA_SIZE;
                memcpy(pkt->data, final_data, final_len);
                pkt->len = final_len;
            }

            pkt->local_idx = local_idx;

            if (mpmc_ring_enqueue(&pl->tx_local_rings[local_idx], batch[i]) != 0) {
                pkt_pool_free(&pl->pool, batch[i]);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            } else {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
            }
        }

        /* Periodic GC of fragment table */
        if (frag_tbl && ++gc_counter >= 1000) {
            frag_table_gc(frag_tbl);
            gc_counter = 0;
        }
    }

    if (frag_tbl) free(frag_tbl);
    return NULL;
}

/* ================================================================
 * Stage 3: TX Threads (send packets out)
 * ================================================================ */

static void *tx_wan_thread(void *arg) {
    struct tx_thread_args *a = (struct tx_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;

    pin_thread_to_cpu(a->cpu_id);
    printf("[TX-WAN] shared (polls %d WANs) -> CPU %d\n",
           fwd->wan_count, a->cpu_id);

    uint32_t batch[64];

    while (running) {
        int did_work = 0;

        for (int w = 0; w < fwd->wan_count; w++) {
            int count = mpmc_ring_dequeue_batch(
                &pl->tx_wan_rings[w], batch, 64);
            if (count == 0) continue;
            did_work = 1;

            struct xsk_interface *wan = &fwd->wans[w];

            for (int i = 0; i < count; i++) {
                struct pkt_slot *pkt = &pl->pool.slots[batch[i]];
                interface_send_batch_queue(wan, 0, pkt->data, pkt->len);
                pkt_pool_free(&pl->pool, batch[i]);
            }

            interface_send_flush_queue(wan, 0);
        }

        if (!did_work)
            sched_yield();
    }

    return NULL;
}

static void *tx_local_thread(void *arg) {
    struct tx_thread_args *a = (struct tx_thread_args *)arg;
    struct forwarder *fwd = a->fwd;
    struct pipeline_ctx *pl = &fwd->pipeline;

    pin_thread_to_cpu(a->cpu_id);
    printf("[TX-LOCAL] shared (polls %d LOCALs) -> CPU %d\n",
           fwd->local_count, a->cpu_id);

    uint32_t batch[64];

    while (running) {
        int did_work = 0;

        for (int l = 0; l < fwd->local_count; l++) {
            int count = mpmc_ring_dequeue_batch(
                &pl->tx_local_rings[l], batch, 64);
            if (count == 0) continue;
            did_work = 1;

            struct xsk_interface *local = &fwd->locals[l];
            struct local_config *lcfg = &fwd->cfg->locals[l];

            for (int i = 0; i < count; i++) {
                struct pkt_slot *pkt = &pl->pool.slots[batch[i]];
                interface_send_to_local_batch_queue(local, 0, lcfg,
                                                     pkt->data, pkt->len);
                pkt_pool_free(&pl->pool, batch[i]);
            }

            interface_send_to_local_flush_queue(local, 0);
        }

        if (!did_work)
            sched_yield();
    }

    return NULL;
}

/* ================================================================
 * GC Thread
 * ================================================================ */

static void *gc_thread_fn(void *arg) {
    (void)arg;
    while (running) {
        sleep(10);
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}

/* ================================================================
 * Forwarder init / cleanup / run
 * ================================================================ */

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;

    /* Flow table */
    uint32_t window_size = cfg->wans[0].window_size;
    flow_table_init(&g_flow_table, window_size, cfg->wan_count);
    printf("[FORWARDER] Flow table: window=%u bytes, wan_count=%d\n",
           window_size, cfg->wan_count);

    /* Calculate thread allocation */
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 4) num_cpus = 4;

    int rx_local_count = 1;
    int rx_wan_count = cfg->wan_count;
    int tx_count = 2;   /* 1 TX WAN shared + 1 TX LOCAL */

    int worker_budget = num_cpus - rx_local_count - rx_wan_count - tx_count;
    if (worker_budget < 2) worker_budget = 2;

    int outbound_workers = cfg->num_outbound_workers;
    int inbound_workers = cfg->num_inbound_workers;

    if (outbound_workers <= 0 || inbound_workers <= 0) {
        outbound_workers = (worker_budget + 1) / 2;
        inbound_workers = worker_budget - outbound_workers;
    }

    printf("\n[CPU] ═══════════════════════════════════════════════\n");
    printf("[CPU] Detected %d CPU cores\n", num_cpus);
    printf("[CPU] RX threads: %d LOCAL + %d WAN = %d\n",
           rx_local_count, rx_wan_count, rx_local_count + rx_wan_count);
    printf("[CPU] Workers: %d outbound + %d inbound = %d\n",
           outbound_workers, inbound_workers, outbound_workers + inbound_workers);
    printf("[CPU] TX threads: %d (1 WAN shared + 1 LOCAL)\n", tx_count);
    printf("[CPU] Total: %d threads on %d cores\n",
           rx_local_count + rx_wan_count + outbound_workers + inbound_workers + tx_count,
           num_cpus);
    printf("[CPU] ═══════════════════════════════════════════════\n\n");

    /* Set NIC queue counts: 1 per interface for pipeline model */
    for (int i = 0; i < cfg->local_count; i++)
        interface_set_queue_count(cfg->locals[i].ifname, rx_local_count);
    for (int i = 0; i < cfg->wan_count; i++)
        interface_set_queue_count(cfg->wans[i].ifname, 1);

    /* Init LOCAL interfaces */
    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err_locals;
        }
        fwd->local_count++;
    }

    /* Init WAN interfaces */
    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i],
                                   "bpf/xdp_wan_redirect.o") != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
    }

    /* Init pipeline */
    if (pipeline_init(&fwd->pipeline,
                      outbound_workers, inbound_workers,
                      cfg->wan_count, cfg->local_count,
                      cfg->pipeline_ring_size,
                      cfg->pipeline_pool_size) != 0) {
        fprintf(stderr, "Failed to init pipeline\n");
        goto err_wans;
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
    pipeline_destroy(&fwd->pipeline);
    flow_table_cleanup(&g_flow_table);

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    struct pipeline_ctx *pl = &fwd->pipeline;

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 4) num_cpus = 4;

    /* Count total threads */
    int rx_local_threads = 0;
    for (int i = 0; i < fwd->local_count; i++)
        rx_local_threads += fwd->locals[i].queue_count;

    int rx_wan_threads = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        rx_wan_threads += fwd->wans[i].queue_count;

    int total_threads = rx_local_threads + rx_wan_threads
                      + pl->num_outbound_workers + pl->num_inbound_workers
                      + 2; /* TX WAN + TX LOCAL */

    printf("\n[PIPELINE] ═══════════════════════════════════════════\n");
    printf("[PIPELINE] RX LOCAL threads: %d\n", rx_local_threads);
    printf("[PIPELINE] RX WAN threads:   %d\n", rx_wan_threads);
    printf("[PIPELINE] Outbound workers: %d\n", pl->num_outbound_workers);
    printf("[PIPELINE] Inbound workers:  %d\n", pl->num_inbound_workers);
    printf("[PIPELINE] TX threads:       2 (1 WAN shared + 1 LOCAL)\n");
    printf("[PIPELINE] Total threads:    %d\n", total_threads);
    printf("[PIPELINE] Fragmentation:    packets > %d bytes\n",
           FRAG_MTU - FRAG_PLAIN_HDR_SIZE);
    printf("[PIPELINE] ═══════════════════════════════════════════\n\n");

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    void **all_args = calloc(total_threads, sizeof(void *));
    if (!threads || !all_args) {
        fprintf(stderr, "Failed to allocate thread arrays\n");
        free(threads);
        free(all_args);
        return;
    }

    int cpu = 0;
    int tidx = 0;

    /* --- RX LOCAL threads --- */
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count; q++) {
            struct rx_thread_args *a = calloc(1, sizeof(*a));
            a->fwd = fwd;
            a->iface_idx = i;
            a->queue_idx = q;
            a->cpu_id = cpu % num_cpus;
            all_args[tidx] = a;
            pthread_create(&threads[tidx], NULL, rx_local_thread, a);
            cpu++;
            tidx++;
        }
    }

    /* --- RX WAN threads --- */
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int q = 0; q < fwd->wans[i].queue_count; q++) {
            struct rx_thread_args *a = calloc(1, sizeof(*a));
            a->fwd = fwd;
            a->iface_idx = i;
            a->queue_idx = q;
            a->cpu_id = cpu % num_cpus;
            all_args[tidx] = a;
            pthread_create(&threads[tidx], NULL, rx_wan_thread, a);
            cpu++;
            tidx++;
        }
    }

    /* --- Outbound worker threads --- */
    for (int w = 0; w < pl->num_outbound_workers; w++) {
        struct worker_thread_args *a = calloc(1, sizeof(*a));
        a->fwd = fwd;
        a->worker_id = w;
        a->cpu_id = cpu % num_cpus;
        all_args[tidx] = a;
        pthread_create(&threads[tidx], NULL, outbound_worker_thread, a);
        cpu++;
        tidx++;
    }

    /* --- Inbound worker threads --- */
    for (int w = 0; w < pl->num_inbound_workers; w++) {
        struct worker_thread_args *a = calloc(1, sizeof(*a));
        a->fwd = fwd;
        a->worker_id = w;
        a->cpu_id = cpu % num_cpus;
        all_args[tidx] = a;
        pthread_create(&threads[tidx], NULL, inbound_worker_thread, a);
        cpu++;
        tidx++;
    }

    /* --- TX WAN thread (shared) --- */
    {
        struct tx_thread_args *a = calloc(1, sizeof(*a));
        a->fwd = fwd;
        a->cpu_id = cpu % num_cpus;
        all_args[tidx] = a;
        pthread_create(&threads[tidx], NULL, tx_wan_thread, a);
        cpu++;
        tidx++;
    }

    /* --- TX LOCAL thread --- */
    {
        struct tx_thread_args *a = calloc(1, sizeof(*a));
        a->fwd = fwd;
        a->cpu_id = cpu % num_cpus;
        all_args[tidx] = a;
        pthread_create(&threads[tidx], NULL, tx_local_thread, a);
        cpu++;
        tidx++;
    }

    /* --- GC thread (shares a CPU) --- */
    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread_fn, NULL);

    /* Wait for shutdown */
    while (running)
        sleep(1);

    for (int i = 0; i < tidx; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    for (int i = 0; i < tidx; i++)
        free(all_args[i]);
    free(all_args);
    free(threads);
}

void forwarder_print_stats(struct forwarder *fwd) {
    (void)fwd;
}
