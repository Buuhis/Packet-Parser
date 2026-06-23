#include "cfm.h"
#include "cfm_diag.h"
#include "config.h"

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

#define CFM_INTERVAL_MS 100
#define CFM_TIMEOUT_MS  350

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
    bool is_up;                 
    bool mac_learned;           
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
    struct cfm_ccm_packet pkt;
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
                    cfm_ccm_packet_t rx_pkt;
                    ssize_t rx_bytes = recv(fds[i].fd, &rx_pkt, sizeof(rx_pkt), 0);
                    
                    if (rx_bytes >= (ssize_t)(sizeof(eth_hdr_t) + sizeof(cfm_ccm_hdr_t))) {
                        if (ntohs(rx_pkt.eth.eth_type) == ETH_P_CFM) {
                            uint8_t lvl = (rx_pkt.ccm.md_lvl_version >> 5) & 0x07;
                            uint8_t op = rx_pkt.ccm.opcode;
                            
                            // Process only Level 5 CCM packets
                            if (lvl == 5 && op == CFM_OPCODE_CCM) {
                                uint16_t rx_mep_id = ntohs(rx_pkt.ccm.mep_id);
                                
                                // Find corresponding link by socket
                                for (int j = 0; j < g_link_count; j++) {
                                    if (g_links[j].sock_fd == fds[i].fd) {
                                        pthread_mutex_lock(&g_links[j].lock);
                                        if (!g_links[j].mac_learned) {
                                            // Learn peer's MAC and MEP ID dynamically
                                            memcpy(g_links[j].remote_mac, rx_pkt.eth.src_mac, 6);
                                            g_links[j].remote_mep_id = rx_mep_id;
                                            g_links[j].mac_learned = true;
                                            g_links[j].is_up = true;
                                            g_links[j].last_recv_time = now;
                                            printf("[CFM] Learned remote MAC %02x:%02x:%02x:%02x:%02x:%02x and MEP %d on %s\n",
                                                   g_links[j].remote_mac[0], g_links[j].remote_mac[1], g_links[j].remote_mac[2],
                                                   g_links[j].remote_mac[3], g_links[j].remote_mac[4], g_links[j].remote_mac[5],
                                                   g_links[j].remote_mep_id, g_links[j].ifname);
                                        } else {
                                            // Check if incoming packet matches learned peer
                                            if (rx_mep_id == g_links[j].remote_mep_id &&
                                                memcmp(rx_pkt.eth.src_mac, g_links[j].remote_mac, 6) == 0) {
                                                g_links[j].last_recv_time = now;
                                                g_links[j].is_up = true;
                                            }
                                        }
                                        pthread_mutex_unlock(&g_links[j].lock);
                                        break;
                                    }
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
                    if (g_links[i].mac_learned) {
                        if (now - g_links[i].last_recv_time > CFM_TIMEOUT_MS) {
                            g_links[i].is_up = false;
                        }
                    } else {
                        // Keep UP until MAC is learned
                        g_links[i].is_up = true;
                    }
                    pthread_mutex_unlock(&g_links[i].lock);
                }
            }
            last_tx_time = now;
        }
    }
    return NULL;
}

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

        // Skip interfaces that have a dst_ip configured (these are authen/IP interfaces)
        if (wan->dst_ip != 0) {
            continue;
        }

        int ifindex = if_nametoindex(wan->ifname);
        if (ifindex == 0) {
            fprintf(stderr, "[CFM-INIT] Warning: Interface %s index not found.\n", wan->ifname);
            continue;
        }

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_CFM));
        if (sock < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot create raw socket for %s: %s\n", wan->ifname, strerror(errno));
            continue;
        }

        // Bind socket to specific interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_CFM);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot bind raw socket to %s: %s\n", wan->ifname, strerror(errno));
            close(sock);
            continue;
        }

        // Set non-blocking socket
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        cfm_link_t *link = &g_links[g_link_count];
        strncpy(link->ifname, wan->ifname, IFNAMSIZ - 1);
        link->ifindex = ifindex;
        link->sock_fd = sock;
        
        // Query local MAC address dynamically, fallback to DB configuration
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, wan->ifname, IFNAMSIZ - 1);
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
        link->is_up = true; // Assume UP initially so we don't disrupt traffic before learning
        pthread_mutex_init(&link->lock, NULL);

        g_link_count++;
        initialized_links++;
    }

    if (initialized_links > 0) {
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

bool cfm_is_link_up(int wan_idx) {
    if (wan_idx < 0 || wan_idx >= g_link_count) {
        return false;
    }
    
    pthread_mutex_lock(&g_links[wan_idx].lock);
    bool status = g_links[wan_idx].is_up;
    pthread_mutex_unlock(&g_links[wan_idx].lock);
    
    return status;
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

int failover_select_wan(const struct app_config *cfg, int profile_idx, int initial_wan_idx) {
    if (initial_wan_idx < 0 || initial_wan_idx >= cfg->wan_count) {
        return initial_wan_idx;
    }

    // 1. If the chosen WAN is UP, use it.
    if (cfm_is_link_up(initial_wan_idx)) {
        return initial_wan_idx;
    }

    // 2. If it is DOWN, look for an alternative WAN in the same profile
    if (profile_idx >= 0 && profile_idx < cfg->profile_count) {
        const struct profile_config *p = &cfg->profiles[profile_idx];
        for (int i = 0; i < p->wan_count; i++) {
            int w_idx = p->wan_indices[i];
            if (w_idx >= 0 && w_idx < cfg->wan_count && cfm_is_link_up(w_idx)) {
                return w_idx;
            }
        }
    }

    // 3. Global fallback: If no other WAN in the same profile is UP, search across all WANs
    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfm_is_link_up(i)) {
            return i;
        }
    }

    // 4. Ultimate fallback: if all WANs are down, return the initially selected one
    return initial_wan_idx;
}
