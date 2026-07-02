#include "cfm.h"
#include "cfm_diag.h"
#include "config.h"
#include "forwarder.h"
#include "forwarder_wan.h"
#include "../../inc/db/db_env.h"
#include <libpq-fe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <libgen.h>

#define CFM_INTERVAL_MS 100
#define CFM_TIMEOUT_MS  350
#define CFM_STARTUP_TIMEOUT_MS 1000

typedef struct cfm_link {
    pthread_mutex_t lock;       
    uint64_t last_recv_time;    
    int ifindex;                
    int sock_fd;                
    int local_mep_id;           
    int remote_mep_id;          
    uint32_t tx_seq;            
    char ifname[IFNAMSIZ];      
    uint8_t local_mac[6];       
    uint8_t remote_mac[6];      
    cfm_link_state_t state;     
    bool mac_learned;           
    int cfg_wan_idx;            
    int wan_dp;                 
    
    // ITU-T Y.1731 quality metrics
    uint32_t rtt_us;
    uint32_t jitter_us;
    float    loss_rate;
    int      loss_mechanism; // 1 = LMM, 2 = SLM
    
    // SLM/SLR sequence tracking
    uint32_t tx_slm_seq;
    uint32_t rx_slr_count;
    uint32_t tx_slm_count;
    
    // LMM/LMR previous counters (initiator)
    uint32_t prev_tx_fc_f;
    uint32_t prev_rx_fc_f;
    uint32_t prev_tx_fc_b;
    uint32_t prev_rx_fc_b;

    // Failover and threshold settings
    int latency_threshold_ms;
    bool latency_enable;
    int loss_threshold_pct;
    bool loss_enable;
    int latency_duration_sec;
    int loss_duration_sec;

    int consecutive_fails;
    int consecutive_successes;
    bool quality_is_bad;

    uint64_t last_dmm_tx_time;
    uint64_t last_lmm_tx_time;
} cfm_link_t;

static cfm_link_t g_links[MAX_INTERFACES];
static int g_link_count = 0;

static pthread_t g_cfm_thread;
static volatile bool g_cfm_running = false;
static pthread_mutex_t g_cfm_init_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void send_ccm_packet(cfm_link_t *link) {
    cfm_ccm_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    // 1. Ethernet Header
    // If MAC is learned, use Unicast to bypass ISP multicast filters. Otherwise, use Multicast.
    pthread_mutex_lock(&link->lock);
    if (link->mac_learned) {
        memcpy(pkt.eth.dst_mac, link->remote_mac, 6);
    } else {
        memcpy(pkt.eth.dst_mac, CFM_MULTICAST_MAC, 6);
    }
    memcpy(pkt.eth.src_mac, link->local_mac, 6);
    pkt.eth.eth_type = htons(ETH_P_CFM);

    // 2. CFM CCM Header
    pkt.ccm.md_lvl_version = 0xA0; // Level 5, Version 0
    pkt.ccm.opcode = CFM_OPCODE_CCM;
    pkt.ccm.flags = 4;             // 100ms interval
    pkt.ccm.first_tlv_offset = 70;
    pkt.ccm.seq_number = htonl(link->tx_seq++);
    pkt.ccm.mep_id = htons(link->local_mep_id);
    
    // Fill MAID name for identification
    snprintf((char *)pkt.ccm.maid, sizeof(pkt.ccm.maid), "MA-WAN-PORT-%.16s", link->ifname);
    
    pkt.end_tlv = 0;

    // Send packet
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = link->ifindex;
    sll.sll_halen = 6;
    if (link->mac_learned) {
        memcpy(sll.sll_addr, link->remote_mac, 6);
    } else {
        memcpy(sll.sll_addr, CFM_MULTICAST_MAC, 6);
    }
    pthread_mutex_unlock(&link->lock);

    if (sendto(link->sock_fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        // Silent fail to avoid flooding stdout/stderr in case of temporary driver issues
    }
}

static int get_interface_counters(const char *ifname, uint32_t *rx_packets, uint32_t *tx_packets) {
    char path[256];
    FILE *fp;
    unsigned long val;
    
    if (rx_packets) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", ifname);
        fp = fopen(path, "r");
        if (!fp) return -1;
        if (fscanf(fp, "%lu", &val) != 1) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
        *rx_packets = (uint32_t)val;
    }
    
    if (tx_packets) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", ifname);
        fp = fopen(path, "r");
        if (!fp) return -1;
        if (fscanf(fp, "%lu", &val) != 1) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
        *tx_packets = (uint32_t)val;
    }
    return 0;
}

static void send_y1731_packet(cfm_link_t *link, uint8_t opcode) {
    uint8_t tx_buf[1024];
    memset(tx_buf, 0, sizeof(tx_buf));
    size_t pkt_len = 0;
    
    eth_hdr_t *eth = (eth_hdr_t *)tx_buf;
    pthread_mutex_lock(&link->lock);
    memcpy(eth->dst_mac, link->remote_mac, 6);
    memcpy(eth->src_mac, link->local_mac, 6);
    eth->eth_type = htons(ETH_P_CFM);
    
    if (opcode == Y1731_OPCODE_DMM) {
        y1731_dmm_dmr_hdr_t *dmm = (y1731_dmm_dmr_hdr_t *)(tx_buf + sizeof(eth_hdr_t));
        dmm->md_lvl_version = 0xA0; // Level 5
        dmm->opcode = Y1731_OPCODE_DMM;
        dmm->flags = 0;
        dmm->first_tlv_offset = 32;
        
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        dmm->tx_timestamp_f.sec = htonl((uint32_t)ts.tv_sec);
        dmm->tx_timestamp_f.nsec = htonl((uint32_t)ts.tv_nsec);
        pkt_len = sizeof(y1731_dmm_dmr_packet_t);
    } 
    else if (opcode == Y1731_OPCODE_LMM) {
        y1731_lmm_lmr_hdr_t *lmm = (y1731_lmm_lmr_hdr_t *)(tx_buf + sizeof(eth_hdr_t));
        lmm->md_lvl_version = 0xA0;
        lmm->opcode = Y1731_OPCODE_LMM;
        lmm->flags = 0;
        lmm->first_tlv_offset = 12;
        
        uint32_t tx_packets = 0;
        get_interface_counters(link->ifname, NULL, &tx_packets);
        lmm->tx_fc_f = htonl(tx_packets);
        link->prev_tx_fc_f = tx_packets;
        pkt_len = sizeof(y1731_lmm_lmr_packet_t);
    } 
    else if (opcode == Y1731_OPCODE_SLM) {
        y1731_slm_slr_hdr_t *slm = (y1731_slm_slr_hdr_t *)(tx_buf + sizeof(eth_hdr_t));
        slm->md_lvl_version = 0xA0;
        slm->opcode = Y1731_OPCODE_SLM;
        slm->flags = 0;
        slm->first_tlv_offset = 16;
        
        slm->src_mep_id = htons((uint16_t)link->local_mep_id);
        slm->responder_mep_id = 0;
        slm->test_id = 0;
        
        link->tx_slm_seq++;
        slm->tx_fc_l = htonl(link->tx_slm_seq);
        link->tx_slm_count++;
        pkt_len = sizeof(y1731_slm_slr_packet_t);
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = link->ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, link->remote_mac, 6);
    int sock_fd = link->sock_fd;
    pthread_mutex_unlock(&link->lock);
    
    if (pkt_len > 0 && sock_fd >= 0) {
        sendto(sock_fd, tx_buf, pkt_len, 0, (struct sockaddr *)&sll, sizeof(sll));
    }
}

static void evaluate_link_quality(cfm_link_t *link, bool is_fail, const char *metric_name, float val, float thresh) {
    if (is_fail) {
        link->consecutive_fails++;
        link->consecutive_successes = 0;
        printf("[Y1731] Probe fail on %s (%s: %.2f > %.2f). Fails: %d/3\n",
               link->ifname, metric_name, val, thresh, link->consecutive_fails);
        if (link->consecutive_fails >= 3 && !link->quality_is_bad) {
            link->quality_is_bad = true;
            printf("[Y1731] !!! WAN %s quality marked BAD due to consecutive %s failures !!!\n",
                   link->ifname, metric_name);
        }
    } else {
        bool latency_ok = true;
        bool loss_ok = true;

        if (link->latency_enable && link->rtt_us > 0) {
            float rtt_ms = (float)link->rtt_us / 1000.0f;
            if (rtt_ms > (float)link->latency_threshold_ms * 0.8f) {
                latency_ok = false;
            }
        }
        if (link->loss_enable) {
            float loss_pct = link->loss_rate * 100.0f;
            if (loss_pct > (float)link->loss_threshold_pct * 0.8f) {
                loss_ok = false;
            }
        }

        if (latency_ok && loss_ok) {
            link->consecutive_successes++;
            link->consecutive_fails = 0;
            printf("[Y1731] Probe success on %s (%s: %.2f <= 80%% of %.2f). Successes: %d/10\n",
                   link->ifname, metric_name, val, thresh, link->consecutive_successes);
            if (link->consecutive_successes >= 10 && link->quality_is_bad) {
                link->quality_is_bad = false;
                printf("[Y1731] !!! WAN %s quality recovered to GOOD after 10 consecutive successes !!!\n",
                       link->ifname);
            }
        }
    }
}

static void *cfm_monitor_thread(void *arg) {
    (void)arg;
    struct pollfd fds[MAX_INTERFACES];
    uint64_t last_tx_time = get_time_ms();

    while (g_cfm_running) {
        int active_fds = 0;
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd >= 0) {
                fds[active_fds].fd = g_links[i].sock_fd;
                fds[active_fds].events = POLLIN;
                fds[active_fds].revents = 0;
                active_fds++;
            }
        }

        if (active_fds == 0) {
            usleep(100000);
            continue;
        }

        // Poll raw sockets for incoming CFM frames with 10ms timeout
        int ret = poll(fds, active_fds, 10);
        if (ret > 0) {
            uint64_t now = get_time_ms();
            for (int i = 0; i < active_fds; i++) {
                if (fds[i].revents & POLLIN) {
                    uint8_t rx_buf[1024];
                    struct sockaddr_ll sll_rx;
                    socklen_t sll_rx_len = sizeof(sll_rx);
                    ssize_t rx_bytes = recvfrom(fds[i].fd, rx_buf, sizeof(rx_buf), 0, (struct sockaddr *)&sll_rx, &sll_rx_len);
                    
                    if (rx_bytes >= (ssize_t)(sizeof(eth_hdr_t) + 4)) {
                        eth_hdr_t *eth = (eth_hdr_t *)rx_buf;
                        if (ntohs(eth->eth_type) == ETH_P_CFM) {
                            uint8_t *cfm_pdu = rx_buf + sizeof(eth_hdr_t);
                            uint8_t lvl = (cfm_pdu[0] >> 5) & 0x07;
                            uint8_t op = cfm_pdu[1];
                            
                            // Process only Level 5 CCM packets
                            if (lvl == 5) {
                                cfm_ccm_hdr_t *ccm = (cfm_ccm_hdr_t *)cfm_pdu;
                                uint16_t rx_mep_id = 0;
                                if (op == CFM_OPCODE_CCM) {
                                    rx_mep_id = ntohs(ccm->mep_id);
                                }
                                
                                // Find corresponding link by socket
                                cfm_link_t *link = NULL;
                                for (int j = 0; j < g_link_count; j++) {
                                    if (g_links[j].sock_fd == fds[i].fd) {
                                        link = &g_links[j];
                                        break;
                                    }
                                }
                                
                                if (link) {
                                    pthread_mutex_lock(&link->lock);
                                    
                                    if (op == CFM_OPCODE_CCM) {
                                        if (!link->mac_learned) {
                                            // Learn peer's MAC and MEP ID dynamically
                                            memcpy(link->remote_mac, eth->src_mac, 6);
                                            link->remote_mep_id = rx_mep_id;
                                            link->mac_learned = true;
                                            cfm_link_state_t old_state = link->state;
                                            link->state = CFM_LINK_STATE_UP;
                                            link->last_recv_time = now;
                                            printf("[CFM] Learned remote MAC %02x:%02x:%02x:%02x:%02x:%02x and MEP %d on %s\n",
                                                link->remote_mac[0], link->remote_mac[1], link->remote_mac[2],
                                                link->remote_mac[3], link->remote_mac[4], link->remote_mac[5],
                                                link->remote_mep_id, link->ifname);
                                            if (link->state != old_state) {
                                                const char *old_str = (old_state == CFM_LINK_STATE_INIT) ? "INIT" : ((old_state == CFM_LINK_STATE_UP) ? "UP" : "DOWN");
                                                printf("[CFM] Link status on %s changed: %s -> UP\n", link->ifname, old_str);
                                            }
                                        } else {
                                            // Check if incoming packet matches learned peer
                                            if (rx_mep_id == link->remote_mep_id &&
                                                memcmp(eth->src_mac, link->remote_mac, 6) == 0) {
                                                link->last_recv_time = now;
                                                cfm_link_state_t old_state = link->state;
                                                link->state = CFM_LINK_STATE_UP;
                                                if (link->state != old_state) {
                                                    const char *old_str = (old_state == CFM_LINK_STATE_INIT) ? "INIT" : ((old_state == CFM_LINK_STATE_UP) ? "UP" : "DOWN");
                                                    printf("[CFM] Link status on %s changed: %s -> UP\n", link->ifname, old_str);
                                                }
                                            }
                                        }
                                    }
                                    else if (op == Y1731_OPCODE_DMM) {
                                        // Responder: Respond to DMM with DMR
                                        y1731_dmm_dmr_hdr_t *dmm = (y1731_dmm_dmr_hdr_t *)cfm_pdu;
                                        struct timespec ts_rx, ts_tx;
                                        clock_gettime(CLOCK_MONOTONIC, &ts_rx);
                                        
                                        y1731_dmm_dmr_packet_t tx_pkt;
                                        memset(&tx_pkt, 0, sizeof(tx_pkt));
                                        
                                        memcpy(tx_pkt.eth.dst_mac, eth->src_mac, 6);
                                        memcpy(tx_pkt.eth.src_mac, link->local_mac, 6);
                                        tx_pkt.eth.eth_type = htons(ETH_P_CFM);
                                        
                                        tx_pkt.dmm_dmr.md_lvl_version = 0xA0;
                                        tx_pkt.dmm_dmr.opcode = Y1731_OPCODE_DMR;
                                        tx_pkt.dmm_dmr.flags = 0;
                                        tx_pkt.dmm_dmr.first_tlv_offset = 32;
                                        
                                        tx_pkt.dmm_dmr.tx_timestamp_f = dmm->tx_timestamp_f;
                                        
                                        tx_pkt.dmm_dmr.rx_timestamp_f.sec = htonl((uint32_t)ts_rx.tv_sec);
                                        tx_pkt.dmm_dmr.rx_timestamp_f.nsec = htonl((uint32_t)ts_rx.tv_nsec);
                                        
                                        clock_gettime(CLOCK_MONOTONIC, &ts_tx);
                                        tx_pkt.dmm_dmr.tx_timestamp_b.sec = htonl((uint32_t)ts_tx.tv_sec);
                                        tx_pkt.dmm_dmr.tx_timestamp_b.nsec = htonl((uint32_t)ts_tx.tv_nsec);
                                        
                                        struct sockaddr_ll sll_tx;
                                        memset(&sll_tx, 0, sizeof(sll_tx));
                                        sll_tx.sll_family = AF_PACKET;
                                        sll_tx.sll_ifindex = link->ifindex;
                                        sll_tx.sll_halen = 6;
                                        memcpy(sll_tx.sll_addr, eth->src_mac, 6);
                                        
                                        sendto(link->sock_fd, &tx_pkt, sizeof(tx_pkt), 0, (struct sockaddr *)&sll_tx, sizeof(sll_tx));
                                        printf("[Y1731] Responded to DMM with DMR on %s\n", link->ifname);
                                    }
                                    else if (op == Y1731_OPCODE_LMM) {
                                        // Responder: Respond to LMM with LMR
                                        y1731_lmm_lmr_hdr_t *lmm = (y1731_lmm_lmr_hdr_t *)cfm_pdu;
                                        uint32_t rx_packets = 0, tx_packets = 0;
                                        get_interface_counters(link->ifname, &rx_packets, &tx_packets);
                                        
                                        y1731_lmm_lmr_packet_t tx_pkt;
                                        memset(&tx_pkt, 0, sizeof(tx_pkt));
                                        
                                        memcpy(tx_pkt.eth.dst_mac, eth->src_mac, 6);
                                        memcpy(tx_pkt.eth.src_mac, link->local_mac, 6);
                                        tx_pkt.eth.eth_type = htons(ETH_P_CFM);
                                        
                                        tx_pkt.lmm_lmr.md_lvl_version = 0xA0;
                                        tx_pkt.lmm_lmr.opcode = Y1731_OPCODE_LMR;
                                        tx_pkt.lmm_lmr.flags = 0;
                                        tx_pkt.lmm_lmr.first_tlv_offset = 12;
                                        
                                        tx_pkt.lmm_lmr.tx_fc_f = lmm->tx_fc_f;
                                        tx_pkt.lmm_lmr.rx_fc_f = htonl(rx_packets);
                                        tx_pkt.lmm_lmr.tx_fc_b = htonl(tx_packets);
                                        
                                        struct sockaddr_ll sll_tx;
                                        memset(&sll_tx, 0, sizeof(sll_tx));
                                        sll_tx.sll_family = AF_PACKET;
                                        sll_tx.sll_ifindex = link->ifindex;
                                        sll_tx.sll_halen = 6;
                                        memcpy(sll_tx.sll_addr, eth->src_mac, 6);
                                        
                                        sendto(link->sock_fd, &tx_pkt, sizeof(tx_pkt), 0, (struct sockaddr *)&sll_tx, sizeof(sll_tx));
                                        printf("[Y1731] Responded to LMM with LMR on %s (RxFC: %u, TxFC: %u)\n", link->ifname, rx_packets, tx_packets);
                                    }
                                    else if (op == Y1731_OPCODE_SLM) {
                                        // Responder: Respond to SLM with SLR
                                        y1731_slm_slr_hdr_t *slm = (y1731_slm_slr_hdr_t *)cfm_pdu;
                                        
                                        y1731_slm_slr_packet_t tx_pkt;
                                        memset(&tx_pkt, 0, sizeof(tx_pkt));
                                        
                                        memcpy(tx_pkt.eth.dst_mac, eth->src_mac, 6);
                                        memcpy(tx_pkt.eth.src_mac, link->local_mac, 6);
                                        tx_pkt.eth.eth_type = htons(ETH_P_CFM);
                                        
                                        tx_pkt.slm_slr.md_lvl_version = 0xA0;
                                        tx_pkt.slm_slr.opcode = Y1731_OPCODE_SLR;
                                        tx_pkt.slm_slr.flags = 0;
                                        tx_pkt.slm_slr.first_tlv_offset = 16;
                                        
                                        tx_pkt.slm_slr.src_mep_id = slm->src_mep_id;
                                        tx_pkt.slm_slr.responder_mep_id = htons((uint16_t)link->local_mep_id);
                                        tx_pkt.slm_slr.test_id = slm->test_id;
                                        tx_pkt.slm_slr.tx_fc_l = slm->tx_fc_l;
                                        tx_pkt.slm_slr.tx_fc_b = slm->tx_fc_l; // Reflected
                                        
                                        struct sockaddr_ll sll_tx;
                                        memset(&sll_tx, 0, sizeof(sll_tx));
                                        sll_tx.sll_family = AF_PACKET;
                                        sll_tx.sll_ifindex = link->ifindex;
                                        sll_tx.sll_halen = 6;
                                        memcpy(sll_tx.sll_addr, eth->src_mac, 6);
                                        
                                        sendto(link->sock_fd, &tx_pkt, sizeof(tx_pkt), 0, (struct sockaddr *)&sll_tx, sizeof(sll_tx));
                                        printf("[Y1731] Responded to SLM with SLR on %s (Seq: %u)\n", link->ifname, ntohl(slm->tx_fc_l));
                                    }
                                    else if (op == Y1731_OPCODE_DMR) {
                                        // Initiator: Process DMR response to calculate RTT & Jitter
                                        y1731_dmm_dmr_hdr_t *dmr = (y1731_dmm_dmr_hdr_t *)cfm_pdu;
                                        struct timespec ts4;
                                        clock_gettime(CLOCK_MONOTONIC, &ts4);
                                        
                                        uint32_t t1_sec = ntohl(dmr->tx_timestamp_f.sec);
                                        uint32_t t1_nsec = ntohl(dmr->tx_timestamp_f.nsec);
                                        uint32_t t2_sec = ntohl(dmr->rx_timestamp_f.sec);
                                        uint32_t t2_nsec = ntohl(dmr->rx_timestamp_f.nsec);
                                        uint32_t t3_sec = ntohl(dmr->tx_timestamp_b.sec);
                                        uint32_t t3_nsec = ntohl(dmr->tx_timestamp_b.nsec);
                                        uint32_t t4_sec = (uint32_t)ts4.tv_sec;
                                        uint32_t t4_nsec = (uint32_t)ts4.tv_nsec;
                                        
                                        int64_t t41_us = ((int64_t)t4_sec - t1_sec) * 1000000 + ((int64_t)t4_nsec - t1_nsec) / 1000;
                                        int64_t t32_us = ((int64_t)t3_sec - t2_sec) * 1000000 + ((int64_t)t3_nsec - t2_nsec) / 1000;
                                        
                                        int64_t rtt_us = t41_us - t32_us;
                                        if (rtt_us < 0) rtt_us = 0;
                                        
                                        float alpha = 0.2f;
                                        if (link->rtt_us == 0) {
                                            link->rtt_us = (uint32_t)rtt_us;
                                            link->jitter_us = 0;
                                        } else {
                                            int32_t diff = (int32_t)rtt_us - (int32_t)link->rtt_us;
                                            uint32_t abs_diff = (diff < 0) ? -diff : diff;
                                            link->jitter_us = (uint32_t)((1.0f - alpha) * link->jitter_us + alpha * abs_diff);
                                            link->rtt_us = (uint32_t)((1.0f - alpha) * link->rtt_us + alpha * rtt_us);
                                        }
                                        printf("[Y1731] Received DMR on %s: RTT = %u us, Jitter = %u us\n", link->ifname, link->rtt_us, link->jitter_us);
                                        if (link->latency_enable) {
                                            float rtt_ms = (float)link->rtt_us / 1000.0f;
                                            bool is_fail = (rtt_ms > (float)link->latency_threshold_ms);
                                            if (is_fail || rtt_ms <= (float)link->latency_threshold_ms * 0.8f) {
                                                evaluate_link_quality(link, is_fail, "latency", rtt_ms, (float)link->latency_threshold_ms);
                                            }
                                        }
                                    }
                                    else if (op == Y1731_OPCODE_LMR) {
                                        // Initiator: Process LMR response to calculate hardware packet loss
                                        y1731_lmm_lmr_hdr_t *lmr = (y1731_lmm_lmr_hdr_t *)cfm_pdu;
                                        uint32_t t_xfcf = ntohl(lmr->tx_fc_f);
                                        uint32_t r_xfcf = ntohl(lmr->rx_fc_f);
                                        uint32_t t_xfcb = ntohl(lmr->tx_fc_b);
                                        
                                        uint32_t r_xfcb = 0;
                                        get_interface_counters(link->ifname, &r_xfcb, NULL);
                                        
                                        if (link->prev_tx_fc_f != 0 && link->prev_rx_fc_f != 0 &&
                                            link->prev_tx_fc_b != 0 && link->prev_rx_fc_b != 0) {
                                            
                                            uint32_t tx_diff_init = t_xfcf - link->prev_tx_fc_f;
                                            uint32_t rx_diff_resp = r_xfcf - link->prev_rx_fc_f;
                                            uint32_t tx_diff_resp = t_xfcb - link->prev_tx_fc_b;
                                            uint32_t rx_diff_init = r_xfcb - link->prev_rx_fc_b;
                                            
                                            int32_t loss_far = (int32_t)(tx_diff_init - rx_diff_resp);
                                            int32_t loss_near = (int32_t)(tx_diff_resp - rx_diff_init);
                                            if (loss_far < 0) loss_far = 0;
                                            if (loss_near < 0) loss_near = 0;
                                            
                                            uint32_t total_loss = loss_far + loss_near;
                                            uint32_t total_sent = tx_diff_init + tx_diff_resp;
                                            
                                            if (total_sent > 0) {
                                                float rate = (float)total_loss / (float)total_sent;
                                                if (rate > 1.0f) rate = 1.0f;
                                                
                                                float alpha = 0.2f;
                                                link->loss_rate = (1.0f - alpha) * link->loss_rate + alpha * rate;
                                                printf("[Y1731] Received LMR on %s: Loss Rate = %.2f%% (LMM)\n", link->ifname, link->loss_rate * 100.0f);
                                                if (link->loss_enable) {
                                                    float loss_pct = link->loss_rate * 100.0f;
                                                    bool is_fail = (loss_pct > (float)link->loss_threshold_pct);
                                                    if (is_fail || loss_pct <= (float)link->loss_threshold_pct * 0.8f) {
                                                        evaluate_link_quality(link, is_fail, "loss", loss_pct, (float)link->loss_threshold_pct);
                                                    }
                                                }
                                            }
                                        }
                                        
                                        link->prev_tx_fc_f = t_xfcf;
                                        link->prev_rx_fc_f = r_xfcf;
                                        link->prev_tx_fc_b = t_xfcb;
                                        link->prev_rx_fc_b = r_xfcb;
                                        link->loss_mechanism = 1; // LMM
                                    }
                                    else if (op == Y1731_OPCODE_SLR) {
                                        // Initiator: Process SLR response to calculate synthetic packet loss
                                        link->rx_slr_count++;
                                        link->loss_mechanism = 2; // SLM
                                        printf("[Y1731] Received SLR on %s: Seq reflected, SLR count = %u\n", link->ifname, link->rx_slr_count);
                                    }
                                    
                                    pthread_mutex_unlock(&link->lock);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Periodic TX and timeout evaluation
        uint64_t now = get_time_ms();
        if (now - last_tx_time >= CFM_INTERVAL_MS) {
            for (int i = 0; i < g_link_count; i++) {
                if (g_links[i].sock_fd >= 0) {
                    // Send out heartbeat
                    send_ccm_packet(&g_links[i]);

                    // Evaluate health status
                    pthread_mutex_lock(&g_links[i].lock);
                    cfm_link_state_t old_state = g_links[i].state;
                    if (g_links[i].mac_learned) {
                        if (now - g_links[i].last_recv_time > CFM_TIMEOUT_MS) {
                            g_links[i].state = CFM_LINK_STATE_DOWN;
                        } else {
                            g_links[i].state = CFM_LINK_STATE_UP;
                        }
                    } else {
                        if (now - g_links[i].last_recv_time > CFM_STARTUP_TIMEOUT_MS) {
                            g_links[i].state = CFM_LINK_STATE_DOWN;
                        } else {
                            g_links[i].state = CFM_LINK_STATE_INIT;
                        }
                    }
                    if (g_links[i].state != old_state) {
                        const char *old_str = (old_state == CFM_LINK_STATE_INIT) ? "INIT" : ((old_state == CFM_LINK_STATE_UP) ? "UP" : "DOWN");
                        const char *new_str = (g_links[i].state == CFM_LINK_STATE_INIT) ? "INIT" : ((g_links[i].state == CFM_LINK_STATE_UP) ? "UP" : "DOWN");
                        printf("[CFM] Link status on %s changed: %s -> %s\n", g_links[i].ifname, old_str, new_str);
                    }
                    pthread_mutex_unlock(&g_links[i].lock);
                }
            }
            last_tx_time = now;
        }

        // Periodic Y.1731 probes (DMM + LMM/SLM) based on user configured durations
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd >= 0) {
                pthread_mutex_lock(&g_links[i].lock);
                cfm_link_state_t st = g_links[i].state;
                
                if (st == CFM_LINK_STATE_UP) {
                    // Send DMM if enabled and latency duration has elapsed
                    if (g_links[i].latency_enable) {
                        uint64_t lat_dur_ms = (g_links[i].latency_duration_sec > 0 ? g_links[i].latency_duration_sec : 5) * 1000ULL;
                        if (now - g_links[i].last_dmm_tx_time >= lat_dur_ms) {
                            send_y1731_packet(&g_links[i], Y1731_OPCODE_DMM);
                            g_links[i].last_dmm_tx_time = now;
                        }
                    }

                    // Send LMM/SLM if enabled and loss duration has elapsed
                    if (g_links[i].loss_enable) {
                        uint64_t loss_dur_ms = (g_links[i].loss_duration_sec > 0 ? g_links[i].loss_duration_sec : 5) * 1000ULL;
                        if (now - g_links[i].last_lmm_tx_time >= loss_dur_ms) {
                            uint32_t rx = 0, tx = 0;
                            if (get_interface_counters(g_links[i].ifname, &rx, &tx) == 0) {
                                send_y1731_packet(&g_links[i], Y1731_OPCODE_LMM);
                            } else {
                                send_y1731_packet(&g_links[i], Y1731_OPCODE_SLM);
                            }
                            g_links[i].last_lmm_tx_time = now;
                        }
                    }

                    // Periodic SLM rate calculation
                    if (g_links[i].loss_mechanism == 2 && g_links[i].tx_slm_count >= 10) {
                        float rate = 1.0f - ((float)g_links[i].rx_slr_count / (float)g_links[i].tx_slm_count);
                        if (rate < 0.0f) rate = 0.0f;
                        if (rate > 1.0f) rate = 1.0f;
                        
                        float alpha = 0.2f;
                        g_links[i].loss_rate = (1.0f - alpha) * g_links[i].loss_rate + alpha * rate;
                        printf("[Y1731] Calculated SLR loss rate on %s: Loss Rate = %.2f%% (SLM)\n", g_links[i].ifname, g_links[i].loss_rate * 100.0f);
                        
                        g_links[i].tx_slm_count = 0;
                        g_links[i].rx_slr_count = 0;

                        // Evaluate loss quality for SLM
                        if (g_links[i].loss_enable) {
                            float loss_pct = g_links[i].loss_rate * 100.0f;
                            bool is_fail = (loss_pct > (float)g_links[i].loss_threshold_pct);
                            if (is_fail || loss_pct <= (float)g_links[i].loss_threshold_pct * 0.8f) {
                                evaluate_link_quality(&g_links[i], is_fail, "loss", loss_pct, (float)g_links[i].loss_threshold_pct);
                            }
                        }
                    }
                }
                pthread_mutex_unlock(&g_links[i].lock);
            }
        }
    }
    return NULL;
}
static void get_cfm_bind_interface(const char *phys_ifname, char *bind_ifname, size_t max_len) {
    char path[256];
    char target[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", phys_ifname);
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len != -1) {
        target[len] = '\0';
        char *base = basename(target);
        strncpy(bind_ifname, base, max_len - 1);
        bind_ifname[max_len - 1] = '\0';
    } else {
        strncpy(bind_ifname, phys_ifname, max_len - 1);
        bind_ifname[max_len - 1] = '\0';
    }
}

static void cfm_update_thresholds_internal(bool lock_init);

int cfm_init(const struct app_config *cfg) {
    pthread_mutex_lock(&g_cfm_init_lock);
    if (g_cfm_running) {
        g_cfm_running = false;
        pthread_mutex_unlock(&g_cfm_init_lock);
        pthread_join(g_cfm_thread, NULL);
        pthread_mutex_lock(&g_cfm_init_lock);
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd >= 0) {
                close(g_links[i].sock_fd);
            }
            pthread_mutex_destroy(&g_links[i].lock);
        }
        g_link_count = 0;
    }

    g_link_count = 0;
    memset(g_links, 0, sizeof(g_links));

    int initialized_links = 0;
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++) {
        const struct wan_config *wan = &cfg->wans[i];
        if (strlen(wan->ifname) == 0) continue;

        // Skip interfaces that have a dst_ip configured or have dataplane == 0 (these are authen/IP interfaces)
        if (wan->dst_ip != 0 || wan->dataplane == 0) {
            continue;
        }

        char bind_ifname[IFNAMSIZ];
        get_cfm_bind_interface(wan->ifname, bind_ifname, sizeof(bind_ifname));

        int ifindex = if_nametoindex(bind_ifname);
        if (ifindex == 0) {
            fprintf(stderr, "[CFM-INIT] Warning: Interface %s index not found.\n", bind_ifname);
            continue;
        }

        int dp_idx = 0;
        for (int k = 0; k < i; k++) {
            if (cfg->wans[k].dataplane)
                dp_idx++;
        }

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_CFM));
        if (sock < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot create raw socket for %s: %s\n", bind_ifname, strerror(errno));
            continue;
        }

        // Bind socket to specific interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_CFM);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot bind raw socket to %s: %s\n", bind_ifname, strerror(errno));
            close(sock);
            continue;
        }

        // Join the CFM multicast group to receive multicast CCM frames
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifindex;
        mreq.mr_type = PACKET_MR_MULTICAST;
        mreq.mr_alen = 6;
        memcpy(mreq.mr_address, CFM_MULTICAST_MAC, 6);
        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "[CFM-INIT] Warning: Cannot join multicast group on %s: %s\n", bind_ifname, strerror(errno));
        }

        // Set non-blocking socket
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        cfm_link_t *link = &g_links[g_link_count];
        strncpy(link->ifname, wan->ifname, IFNAMSIZ - 1);
        link->ifindex = ifindex;
        link->sock_fd = sock;
        link->cfg_wan_idx = i;
        link->wan_dp = dp_idx;
        
        // Query local MAC address dynamically, fallback to DB configuration
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, bind_ifname, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(link->local_mac, ifr.ifr_hwaddr.sa_data, 6);
        } else {
            memcpy(link->local_mac, wan->src_mac, 6);
        }

        // Assign local MEP ID based on the local MAC address (13-bit hash)
        link->local_mep_id = ((link->local_mac[4] << 8) | link->local_mac[5]) & 0x1FFF;
        if (link->local_mep_id == 0) link->local_mep_id = 1;

        // Check if destination MAC is configured in the DB
        bool zero_dst_mac = true;
        for (int k = 0; k < 6; k++) {
            if (wan->dst_mac[k] != 0) {
                zero_dst_mac = false;
                break;
            }
        }

        if (!zero_dst_mac) {
            memcpy(link->remote_mac, wan->dst_mac, 6);
            link->remote_mep_id = ((wan->dst_mac[4] << 8) | wan->dst_mac[5]) & 0x1FFF;
            if (link->remote_mep_id == 0) link->remote_mep_id = 1;
            link->mac_learned = true;
        } else {
            memset(link->remote_mac, 0, 6);
            link->remote_mep_id = 0;
            link->mac_learned = false;
        }

        link->last_recv_time = get_time_ms();
        link->tx_seq = 0;
        link->state = CFM_LINK_STATE_INIT;
        pthread_mutex_init(&link->lock, NULL);

        link->latency_threshold_ms = 0;
        link->latency_enable = false;
        link->loss_threshold_pct = 0;
        link->loss_enable = false;
        link->latency_duration_sec = 0;
        link->loss_duration_sec = 0;
        link->consecutive_fails = 0;
        link->consecutive_successes = 0;
        link->quality_is_bad = false;
        link->last_dmm_tx_time = 0;
        link->last_lmm_tx_time = 0;

        g_link_count++;
        initialized_links++;
    }

    if (initialized_links > 0) {
        cfm_update_thresholds_internal(false);
        g_cfm_running = true;
        if (pthread_create(&g_cfm_thread, NULL, cfm_monitor_thread, NULL) != 0) {
            fprintf(stderr, "[CFM-INIT] Error: Failed to create CFM monitor thread.\n");
            g_cfm_running = false;
            for (int i = 0; i < g_link_count; i++) {
                close(g_links[i].sock_fd);
                pthread_mutex_destroy(&g_links[i].lock);
            }
            g_link_count = 0;
            pthread_mutex_unlock(&g_cfm_init_lock);
            return -1;
        }
        printf("[CFM-INIT] CFM initialized on %d interfaces.\n", initialized_links);
    } else {
        printf("[CFM-INIT] No WAN interfaces initialized for CFM.\n");
    }

    pthread_mutex_unlock(&g_cfm_init_lock);
    return 0;
}

static void cfm_update_thresholds_internal(bool lock_init) {
    struct ne_postgres_conn pg;
    memset(&pg, 0, sizeof(pg));
    if (load_ne_env() != 0) {
        // Envs loaded
    }
    if (ne_postgres_conn_fill(&pg) != 0) {
        fprintf(stderr, "[CFM-DB] Error: ne_postgres_conn_fill failed\n");
        return;
    }

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CFM-DB] Error: DB Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return;
    }

    if (lock_init) {
        pthread_mutex_lock(&g_cfm_init_lock);
    }
    for (int j = 0; j < g_link_count; j++) {
        const char *param_values[1];
        param_values[0] = g_links[j].ifname;

        PGresult *res = PQexecParams(conn,
            "SELECT w.latency, w.latency_enable, w.loss_percentage, w.loss_enable, p.latency_duration, p.loss_duration "
            "FROM ne_wan w "
            "JOIN ne_profiles p ON w.profile_id = p.id "
            "WHERE w.interface = $1 "
            "ORDER BY w.created_at DESC LIMIT 1",
            1, NULL, param_values, NULL, NULL, 0);

        if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            pthread_mutex_lock(&g_links[j].lock);
            
            // Read latency
            int col_lat = PQfnumber(res, "latency");
            int col_lat_en = PQfnumber(res, "latency_enable");
            if (col_lat >= 0 && !PQgetisnull(res, 0, col_lat)) {
                g_links[j].latency_threshold_ms = atoi(PQgetvalue(res, 0, col_lat));
            }
            if (col_lat_en >= 0 && !PQgetisnull(res, 0, col_lat_en)) {
                const char *val = PQgetvalue(res, 0, col_lat_en);
                g_links[j].latency_enable = (val[0] == 't' || val[0] == '1');
            }

            // Read loss
            int col_loss = PQfnumber(res, "loss_percentage");
            int col_loss_en = PQfnumber(res, "loss_enable");
            if (col_loss >= 0 && !PQgetisnull(res, 0, col_loss)) {
                g_links[j].loss_threshold_pct = atoi(PQgetvalue(res, 0, col_loss));
            }
            if (col_loss_en >= 0 && !PQgetisnull(res, 0, col_loss_en)) {
                const char *val = PQgetvalue(res, 0, col_loss_en);
                g_links[j].loss_enable = (val[0] == 't' || val[0] == '1');
            }

            // Read durations
            int col_lat_dur = PQfnumber(res, "latency_duration");
            int col_loss_dur = PQfnumber(res, "loss_duration");
            if (col_lat_dur >= 0 && !PQgetisnull(res, 0, col_lat_dur)) {
                g_links[j].latency_duration_sec = atoi(PQgetvalue(res, 0, col_lat_dur));
            }
            if (col_loss_dur >= 0 && !PQgetisnull(res, 0, col_loss_dur)) {
                g_links[j].loss_duration_sec = atoi(PQgetvalue(res, 0, col_loss_dur));
            }

            pthread_mutex_unlock(&g_links[j].lock);

            printf("[CFM-DB] Query OK for %s: latency=%d/%d (dur=%ds), loss=%d/%d (dur=%ds)\n",
                   g_links[j].ifname,
                   g_links[j].latency_threshold_ms, g_links[j].latency_enable, g_links[j].latency_duration_sec,
                   g_links[j].loss_threshold_pct, g_links[j].loss_enable, g_links[j].loss_duration_sec);
        } else {
            fprintf(stderr, "[CFM-DB] Warning: No WAN thresholds found in DB for %s (query status: %s)\n",
                    g_links[j].ifname, PQresultErrorMessage(res));
        }
        PQclear(res);
    }
    if (lock_init) {
        pthread_mutex_unlock(&g_cfm_init_lock);
    }

    PQfinish(conn);
}

void cfm_update_thresholds(const struct app_config *cfg) {
    (void)cfg;
    cfm_update_thresholds_internal(true);
}


bool cfm_is_link_up(int wan_dp) {
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].wan_dp == wan_dp) {
            pthread_mutex_lock(&g_links[i].lock);
            cfm_link_state_t state = g_links[i].state;
            bool bad = g_links[i].quality_is_bad;
            pthread_mutex_unlock(&g_links[i].lock);
            if (bad) return false;
            return (state == CFM_LINK_STATE_UP || state == CFM_LINK_STATE_INIT);
        }
    }
    return true;
}

int cfm_get_link_state(int wan_dp) {
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].wan_dp == wan_dp) {
            pthread_mutex_lock(&g_links[i].lock);
            int state = (int)g_links[i].state;
            pthread_mutex_unlock(&g_links[i].lock);
            return state;
        }
    }
    return (int)CFM_LINK_STATE_DOWN;
}

int cfm_get_link_quality(int wan_dp, y1731_metrics_t *metrics) {
    if (!metrics) return -1;
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].wan_dp == wan_dp) {
            pthread_mutex_lock(&g_links[i].lock);
            metrics->rtt_us = g_links[i].rtt_us;
            metrics->jitter_us = g_links[i].jitter_us;
            metrics->loss_rate = g_links[i].loss_rate;
            metrics->loss_mechanism = g_links[i].loss_mechanism;
            pthread_mutex_unlock(&g_links[i].lock);
            return 0;
        }
    }
    return -2;
}

void cfm_cleanup(void) {
    pthread_mutex_lock(&g_cfm_init_lock);
    if (!g_cfm_running) {
        pthread_mutex_unlock(&g_cfm_init_lock);
        return;
    }

    g_cfm_running = false;
    pthread_join(g_cfm_thread, NULL);

    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].sock_fd >= 0) {
            close(g_links[i].sock_fd);
        }
        pthread_mutex_destroy(&g_links[i].lock);
    }
    g_link_count = 0;
    
    printf("[CFM-CLEANUP] CFM diagnostic daemon stopped.\n");
    pthread_mutex_unlock(&g_cfm_init_lock);
}
