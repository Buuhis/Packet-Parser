#include "../inc/pqc_l2_handshake.h"
#include "pqc_handshake.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <poll.h>
#include <pthread.h>


static struct pqc_l2_reassemble *g_reassemble_list = NULL;
static pthread_mutex_t g_reassemble_mutex = PTHREAD_MUTEX_INITIALIZER;


static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Helper to find interface MAC address
static int get_local_mac(int sock, const char *ifname, uint8_t mac[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int pqc_l2_init_peer(struct pqc_l2_peer *peer, const char *ifname) {
    if (!peer || !ifname) return -1;
    memset(peer, 0, sizeof(*peer));
    strncpy(peer->ifname, ifname, sizeof(peer->ifname) - 1);

    // Create Raw socket bound to physical Layer 2 protocol handling
    peer->raw_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (peer->raw_sock_fd < 0) {
        perror("[PQC-L2] Failed to create SOCK_RAW");
        return -1;
    }

    if (get_local_mac(peer->raw_sock_fd, ifname, peer->local_mac) < 0) {
        fprintf(stderr, "[PQC-L2] Failed to get local MAC for %s\n", ifname);
        close(peer->raw_sock_fd);
        peer->raw_sock_fd = -1;
        return -1;
    }

    // Bind raw socket to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(peer->raw_sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("[PQC-L2] SIOCGIFINDEX failed");
        close(peer->raw_sock_fd);
        peer->raw_sock_fd = -1;
        return -1;
    }
    sll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(peer->raw_sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[PQC-L2] Failed to bind raw socket");
        close(peer->raw_sock_fd);
        peer->raw_sock_fd = -1;
        return -1;
    }

    printf("[PQC-L2] Bound to %s. Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           ifname,
           peer->local_mac[0], peer->local_mac[1], peer->local_mac[2],
           peer->local_mac[3], peer->local_mac[4], peer->local_mac[5]);
    
    return 0;
}

int pqc_l2_discover_peer_mac(struct pqc_l2_peer *peer, int timeout_sec) {
    if (!peer || peer->raw_sock_fd < 0) return -1;

    uint8_t pkt[128];
    memset(pkt, 0, sizeof(pkt));

    // 1. Construct L2 Broadcast Probe Ethernet Header
    memset(pkt, 0xFF, 6); // Destination: Broadcast (FF:FF:FF:FF:FF:FF)
    memcpy(pkt + 6, peer->local_mac, 6); // Source: Local MAC
    pkt[12] = (uint8_t)(PQC_ETH_TYPE_DISCOVERY >> 8);
    pkt[13] = (uint8_t)(PQC_ETH_TYPE_DISCOVERY & 0xFF);

    // 2. Custom L2 Header
    struct pqc_l2_hdr *l2 = (struct pqc_l2_hdr *)(pkt + 14);
    l2->magic = htons(PQC_L2_MAGIC);
    l2->msg_type = PQC_MSG_DISCOVERY_PROBE;

    // Send the discovery broadcast probe
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, peer->ifname, IFNAMSIZ - 1);
    if (ioctl(peer->raw_sock_fd, SIOCGIFINDEX, &ifr) >= 0) {
        sll.sll_ifindex = ifr.ifr_ifindex;
    }
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xFF, 6);

    printf("[PQC-L2] Sending broadcast discovery probe on %s...\n", peer->ifname);
    if (sendto(peer->raw_sock_fd, pkt, 14 + sizeof(struct pqc_l2_hdr), 0, 
               (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[PQC-L2] Broadcast probe send failed");
        return -1;
    }

    // Block & listen for unicast ACK
    struct pollfd pfd;
    pfd.fd = peer->raw_sock_fd;
    pfd.events = POLLIN;

    uint64_t start_ms = get_time_ms();
    uint64_t timeout_ms = (uint64_t)timeout_sec * 1000;

    while (get_time_ms() - start_ms < timeout_ms) {
        int r = poll(&pfd, 1, 500);
        if (r < 0) return -1;
        if (r == 0) continue; // Timeout of single poll step, loop again

        uint8_t rx_buf[2048];
        ssize_t rx_len = recv(peer->raw_sock_fd, rx_buf, sizeof(rx_buf), 0);
        if (rx_len < 14 + (ssize_t)sizeof(struct pqc_l2_hdr)) continue;

        uint16_t et = ((uint16_t)rx_buf[12] << 8) | rx_buf[13];
        if (et != PQC_ETH_TYPE_DISCOVERY) continue;

        struct pqc_l2_hdr *rx_l2 = (struct pqc_l2_hdr *)(rx_buf + 14);
        if (ntohs(rx_l2->magic) != PQC_L2_MAGIC) continue;

        if (rx_l2->msg_type == PQC_MSG_DISCOVERY_ACK) {
            // Extracted learned MAC from incoming Ethernet header source
            memcpy(peer->peer_mac, rx_buf + 6, 6);
            peer->discovered = 1;
            printf("[PQC-L2] DISCOVERED PEER MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   peer->peer_mac[0], peer->peer_mac[1], peer->peer_mac[2],
                   peer->peer_mac[3], peer->peer_mac[4], peer->peer_mac[5]);
            return 0;
        }
    }

    fprintf(stderr, "[PQC-L2] Discovery timed out after %d seconds.\n", timeout_sec);
    return -2;
}

int pqc_l2_send_payload_fragmented(struct pqc_l2_peer *peer, uint32_t msg_id, 
                                   const uint8_t *payload, uint32_t payload_len) {
    if (!peer || peer->raw_sock_fd < 0 || !payload || payload_len == 0) return -1;
    if (!peer->discovered) {
        fprintf(stderr, "[PQC-L2] Cannot send: Peer MAC not discovered yet.\n");
        return -1;
    }

    uint32_t sent_bytes = 0;
    uint16_t frag_count = (uint16_t)((payload_len + PQC_MAX_FRAG_SIZE - 1) / PQC_MAX_FRAG_SIZE);
    uint16_t frag_index = 0;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, peer->ifname, IFNAMSIZ - 1);
    if (ioctl(peer->raw_sock_fd, SIOCGIFINDEX, &ifr) >= 0) {
        sll.sll_ifindex = ifr.ifr_ifindex;
    }
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, peer->peer_mac, 6);

    uint8_t pkt_buf[2048];

    // Unicast Ethernet Header template
    memcpy(pkt_buf, peer->peer_mac, 6);
    memcpy(pkt_buf + 6, peer->local_mac, 6);
    pkt_buf[12] = (uint8_t)(PQC_ETH_TYPE_HANDSHAKE >> 8);
    pkt_buf[13] = (uint8_t)(PQC_ETH_TYPE_HANDSHAKE & 0xFF);

    // Custom L2 Header template
    struct pqc_l2_hdr *l2 = (struct pqc_l2_hdr *)(pkt_buf + 14);
    l2->magic = htons(PQC_L2_MAGIC);
    l2->msg_type = PQC_MSG_HANDSHAKE_DATA;

    while (sent_bytes < payload_len) {
        uint16_t curr_chunk = (uint16_t)(payload_len - sent_bytes);
        if (curr_chunk > PQC_MAX_FRAG_SIZE) {
            curr_chunk = PQC_MAX_FRAG_SIZE;
        }

        // Fill Fragmentation Header
        struct pqc_frag_hdr *frag = (struct pqc_frag_hdr *)(pkt_buf + 14 + sizeof(struct pqc_l2_hdr));
        frag->msg_id = htonl(msg_id);
        frag->total_len = htonl(payload_len);
        frag->frag_count = htons(frag_count);
        frag->frag_index = htons(frag_index);
        frag->payload_len = htons(curr_chunk);

        // Copy chunk payload data
        memcpy(pkt_buf + 14 + sizeof(struct pqc_l2_hdr) + sizeof(struct pqc_frag_hdr), 
               payload + sent_bytes, curr_chunk);

        size_t total_frame_sz = 14 + sizeof(struct pqc_l2_hdr) + sizeof(struct pqc_frag_hdr) + curr_chunk;

        if (sendto(peer->raw_sock_fd, pkt_buf, total_frame_sz, 0, 
                   (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("[PQC-L2] Fragment send failed");
            return -1;
        }

        sent_bytes += curr_chunk;
        frag_index++;
        usleep(50); // Minor pacing delay to protect against RX queue drop in standard kernels
    }

    printf("[PQC-L2] Transmitted msg_id %u: %u bytes split in %u fragments.\n", msg_id, payload_len, frag_count);
    return 0;
}

static void free_reassemble(struct pqc_l2_reassemble *r) {
    if (r) {
        if (r->data_buffer) free(r->data_buffer);
        if (r->frag_bitmap) free(r->frag_bitmap);
        free(r);
    }
}

int pqc_l2_recv_and_process(struct pqc_l2_peer *peer, uint8_t **out_payload, uint32_t *out_msg_id) {
    if (!peer || peer->raw_sock_fd < 0 || !out_payload || !out_msg_id) return -1;
    *out_payload = NULL;

    // Timeout cleanup for active reassemblies
    uint64_t now = get_time_ms();
    pthread_mutex_lock(&g_reassemble_mutex);
    struct pqc_l2_reassemble *curr = g_reassemble_list;
    struct pqc_l2_reassemble *prev = NULL;

    while (curr) {
        if (now - curr->start_time_ms > PQC_L2_TIMEOUT_MS) {
            printf("[PQC-L2-TIMEOUT] Handshake assembly MsgID %u timed out. Dropping.\n", curr->msg_id);
            struct pqc_l2_reassemble *temp = curr->next;
            if (prev) prev->next = temp;
            else g_reassemble_list = temp;
            free_reassemble(curr);
            curr = temp;
        } else {
            prev = curr;
            curr = curr->next;
        }
    }
    pthread_mutex_unlock(&g_reassemble_mutex);

    uint8_t rx_buf[2048];
    ssize_t rx_len = recv(peer->raw_sock_fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT);
    if (rx_len < 14) return 0; // No packets currently on the socket queue (Non-blocking)

    uint16_t et = ((uint16_t)rx_buf[12] << 8) | rx_buf[13];

    // Case 1: L2 Peer Discovery protocol
    if (et == PQC_ETH_TYPE_DISCOVERY) {
        if (rx_len < 14 + (ssize_t)sizeof(struct pqc_l2_hdr)) return 0;
        struct pqc_l2_hdr *rx_l2 = (struct pqc_l2_hdr *)(rx_buf + 14);
        if (ntohs(rx_l2->magic) != PQC_L2_MAGIC) return 0;

        if (rx_l2->msg_type == PQC_MSG_DISCOVERY_PROBE) {
            // Learn MAC instantly from incoming frame source
            memcpy(peer->peer_mac, rx_buf + 6, 6);
            peer->discovered = 1;
            printf("[PQC-L2] Discovery probe received from %02X:%02X:%02X:%02X:%02X:%02X. Learning peer MAC.\n",
                   peer->peer_mac[0], peer->peer_mac[1], peer->peer_mac[2],
                   peer->peer_mac[3], peer->peer_mac[4], peer->peer_mac[5]);

            // Reply immediately with a Unicast ACK frame
            uint8_t reply_pkt[64];
            memset(reply_pkt, 0, sizeof(reply_pkt));
            memcpy(reply_pkt, peer->peer_mac, 6); // Destination: learnt Peer MAC
            memcpy(reply_pkt + 6, peer->local_mac, 6); // Source: Local MAC
            reply_pkt[12] = (uint8_t)(PQC_ETH_TYPE_DISCOVERY >> 8);
            reply_pkt[13] = (uint8_t)(PQC_ETH_TYPE_DISCOVERY & 0xFF);

            struct pqc_l2_hdr *tx_l2 = (struct pqc_l2_hdr *)(reply_pkt + 14);
            tx_l2->magic = htons(PQC_L2_MAGIC);
            tx_l2->msg_type = PQC_MSG_DISCOVERY_ACK;

            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, peer->ifname, IFNAMSIZ - 1);
            if (ioctl(peer->raw_sock_fd, SIOCGIFINDEX, &ifr) >= 0) {
                sll.sll_ifindex = ifr.ifr_ifindex;
            }
            sll.sll_halen = 6;
            memcpy(sll.sll_addr, peer->peer_mac, 6);

            printf("[PQC-L2] Replying with unicast discovery ACK to learned MAC...\n");
            sendto(peer->raw_sock_fd, reply_pkt, 14 + sizeof(struct pqc_l2_hdr), 0,
                   (struct sockaddr *)&sll, sizeof(sll));
        }
        return 0;
    }

    // Case 2: Handshake fragmentation L2 frames
    if (et == PQC_ETH_TYPE_HANDSHAKE) {
        size_t expected_hdr = 14 + sizeof(struct pqc_l2_hdr) + sizeof(struct pqc_frag_hdr);
        if (rx_len < (ssize_t)expected_hdr) return 0;

        struct pqc_l2_hdr *rx_l2 = (struct pqc_l2_hdr *)(rx_buf + 14);
        if (ntohs(rx_l2->magic) != PQC_L2_MAGIC || rx_l2->msg_type != PQC_MSG_HANDSHAKE_DATA) return 0;

        struct pqc_frag_hdr *rx_frag = (struct pqc_frag_hdr *)(rx_buf + 14 + sizeof(struct pqc_l2_hdr));
        uint32_t msg_id = ntohl(rx_frag->msg_id);
        uint32_t total_len = ntohl(rx_frag->total_len);
        uint16_t frag_count = ntohs(rx_frag->frag_count);
        uint16_t frag_index = ntohs(rx_frag->frag_index);
        uint16_t payload_len = ntohs(rx_frag->payload_len);

        if (rx_len < (ssize_t)(expected_hdr + payload_len)) return 0;

        pthread_mutex_lock(&g_reassemble_mutex);
        // Search for active assembly buffer
        struct pqc_l2_reassemble *r = g_reassemble_list;
        while (r) {
            if (r->msg_id == msg_id) break;
            r = r->next;
        }

        // Create a new assembly node if not found
        if (!r) {
            r = (struct pqc_l2_reassemble *)calloc(1, sizeof(*r));
            if (!r) {
                pthread_mutex_unlock(&g_reassemble_mutex);
                return -1;
            }
            r->msg_id = msg_id;
            r->total_len = total_len;
            r->frag_count = frag_count;
            r->data_buffer = (uint8_t *)malloc(total_len);
            r->frag_bitmap = (uint8_t *)calloc((frag_count + 7) / 8, 1);
            r->start_time_ms = get_time_ms();
            
            if (!r->data_buffer || !r->frag_bitmap) {
                free_reassemble(r);
                pthread_mutex_unlock(&g_reassemble_mutex);
                return -1;
            }

            // Insert at the front of the list
            r->next = g_reassemble_list;
            g_reassemble_list = r;
        }

        // Prevent processing duplicate fragments
        int byte_idx = frag_index / 8;
        int bit_idx = frag_index % 8;
        if (!(r->frag_bitmap[byte_idx] & (1 << bit_idx))) {
            // Mark bit as received
            r->frag_bitmap[byte_idx] |= (1 << bit_idx);
            r->frag_received++;

            // Copy fragment payload directly to targeted offset in reassembled buffer
            uint32_t offset = frag_index * PQC_MAX_FRAG_SIZE;
            if (offset + payload_len <= r->total_len) {
                memcpy(r->data_buffer + offset, rx_buf + expected_hdr, payload_len);
            }
        }

        // Check if all fragments are received
        if (r->frag_received == r->frag_count) {
            printf("[PQC-L2] Reassembled complete payload for msg_id %u: total_len=%u\n", msg_id, r->total_len);
            
            // Remove node from reassembly list
            curr = g_reassemble_list;
            prev = NULL;
            while (curr) {
                if (curr->msg_id == msg_id) {
                    if (prev) prev->next = curr->next;
                    else g_reassemble_list = curr->next;
                    break;
                }
                prev = curr;
                curr = curr->next;
            }

            *out_payload = r->data_buffer;
            *out_msg_id = msg_id;
            uint32_t final_len = r->total_len;

            // Free structure metadata, keeping only allocated data_buffer passed out
            free(r->frag_bitmap);
            free(r);

            pthread_mutex_unlock(&g_reassemble_mutex);
            return (int)final_len;
        }

        pthread_mutex_unlock(&g_reassemble_mutex);
    }

    return 0;
}

void pqc_l2_cleanup_peer(struct pqc_l2_peer *peer) {
    if (peer) {
        if (peer->raw_sock_fd >= 0) {
            close(peer->raw_sock_fd);
            peer->raw_sock_fd = -1;
        }
        peer->discovered = 0;
    }
}

int pqc_select_handshake_wan(const struct app_config *cfg, int profile_idx) {
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count) {
        fprintf(stderr, "[PQC-DEBUG] pqc_select_handshake_wan: invalid cfg or profile_idx=%d (profile_count=%d)\n", profile_idx, cfg ? cfg->profile_count : -1);
        return -1;
    }
    const struct profile_config *p = &cfg->profiles[profile_idx];
    fprintf(stderr, "[PQC-DEBUG] profile_idx=%d (id=%d, name=%s), wan_count=%d\n", profile_idx, p->id, p->name, p->wan_count);
    if (p->wan_count <= 0) {
        return -1;
    }
    int chosen_w_idx = p->wan_indices[0];
    for (int w = 0; w < p->wan_count; w++) {
        int w_idx = p->wan_indices[w];
        if (w_idx >= 0 && w_idx < cfg->wan_count) {
            char ip_str[32] = "0.0.0.0";
            struct in_addr addr = { .s_addr = cfg->wans[w_idx].dst_ip };
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            fprintf(stderr, "[PQC-DEBUG]   checking wan %d: index=%d, name=%s, dst_ip=%s (0x%08X)\n",
                    w, w_idx, cfg->wans[w_idx].ifname, ip_str, cfg->wans[w_idx].dst_ip);
            if (cfg->wans[w_idx].dst_ip != 0) {
                chosen_w_idx = w_idx;
                break;
            }
        } else {
            fprintf(stderr, "[PQC-DEBUG]   invalid wan index %d in profile (cfg->wan_count=%d)\n", w_idx, cfg->wan_count);
        }
    }
    return chosen_w_idx;
}

void pqc_get_profile_handshake_params(const struct app_config *cfg, int profile_idx, char *out_peer_ip, const char **out_wan_ifname) {
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count) {
        fprintf(stderr, "[PQC-DEBUG] pqc_get_profile_handshake_params: invalid cfg or profile_idx=%d\n", profile_idx);
        return;
    }
    int chosen_idx = pqc_select_handshake_wan(cfg, profile_idx);
    fprintf(stderr, "[PQC-DEBUG] pqc_get_profile_handshake_params: chosen_idx=%d\n", chosen_idx);
    if (chosen_idx >= 0 && chosen_idx < cfg->wan_count) {
        struct in_addr addr;
        addr.s_addr = cfg->wans[chosen_idx].dst_ip;
        inet_ntop(AF_INET, &addr, out_peer_ip, 64);
        *out_wan_ifname = cfg->wans[chosen_idx].ifname;
        fprintf(stderr, "[PQC-DEBUG] pqc_get_profile_handshake_params: resolved to wan_ifname=%s, peer_ip=%s\n", *out_wan_ifname, out_peer_ip);
    } else {
        fprintf(stderr, "[PQC-DEBUG] pqc_get_profile_handshake_params: failed to choose wan\n");
    }
}

void pqc_handshake_start_all_profiles(struct app_config *cfg) {
    if (!cfg) return;
    for (int p_idx = 0; p_idx < cfg->profile_count; p_idx++) {
        const struct profile_config *p = &cfg->profiles[p_idx];
        
        // Check if there is at least one policy in this profile configured with PQC
        bool has_pqc_policy = false;
        for (int i = 0; i < p->policy_count; i++) {
            int pol_idx = p->policy_indices[i];
            if (pol_idx >= 0 && pol_idx < cfg->policy_count) {
                if (cfg->policies[pol_idx].crypto_mode == CRYPTO_MODE_PQC_GCM) {
                    has_pqc_policy = true;
                    break;
                }
            }
        }

        if (has_pqc_policy) {
            fprintf(stderr, "[PQC-HS] Starting Handshake for Profile %d using tunnel configuration\n", p->id);
            sig_pqc_handshake_start(p->id, "", "");
        }
    }
}
