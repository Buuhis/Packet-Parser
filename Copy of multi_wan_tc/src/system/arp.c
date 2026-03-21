#include "arp.h"
#include "../utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>

#define ARP_CACHE_SIZE 65536
#define HASH_IP(ip) (ntohl(ip) & (ARP_CACHE_SIZE - 1))

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    int valid;
} arp_entry_t;

static arp_entry_t g_arp_cache[ARP_CACHE_SIZE];
static pthread_rwlock_t g_arp_lock = PTHREAD_RWLOCK_INITIALIZER;

typedef struct __attribute__((packed)) {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t op;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_header_t;

void arp_cache_init(void) {
    memset(g_arp_cache, 0, sizeof(g_arp_cache));
    log_info("ARP Cache initialized.");
}

void arp_cache_add(uint32_t ip, const uint8_t mac[6]) {
    uint32_t idx = HASH_IP(ip);
    pthread_rwlock_wrlock(&g_arp_lock);
    g_arp_cache[idx].ip = ip;
    memcpy(g_arp_cache[idx].mac, mac, 6);
    g_arp_cache[idx].valid = 1;
    pthread_rwlock_unlock(&g_arp_lock);
    
    struct in_addr addr = { .s_addr = ip };
    log_info("ARP Cache ADD: %s -> %02x:%02x:%02x:%02x:%02x:%02x", 
             inet_ntoa(addr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int arp_cache_lookup(uint32_t ip, uint8_t mac_out[6]) {
    uint32_t idx = HASH_IP(ip);
    int ret = -1;
    pthread_rwlock_rdlock(&g_arp_lock);
    if (g_arp_cache[idx].valid && g_arp_cache[idx].ip == ip) {
        memcpy(mac_out, g_arp_cache[idx].mac, 6);
        ret = 0;
    }
    pthread_rwlock_unlock(&g_arp_lock);
    return ret;
}

int arp_scanner_scan_subnet(const char *ifname, uint32_t local_ip, uint32_t netmask, const uint8_t local_mac[6]) {
    struct in_addr lip = { .s_addr = local_ip };
    struct in_addr msk = { .s_addr = netmask };
    log_info("ARP Scanner starting on %s (IP: %s, Mask: %s)", ifname, inet_ntoa(lip), inet_ntoa(msk));

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        log_error("ARP Scanner: Failed to open AF_PACKET socket");
        return -1;
    }

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0) {
        log_error("ARP Scanner: Invalid interface %s", ifname);
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ARP),
        .sll_ifindex = ifidx,
        .sll_halen = 6,
    };
    memset(sll.sll_addr, 0xFF, 6);

    uint32_t hs_ip = ntohl(local_ip);
    uint32_t hs_mask = ntohl(netmask);
    uint32_t network = hs_ip & hs_mask;
    uint32_t broadcast = network | (~hs_mask);

    struct {
        struct ethhdr eth;
        arp_header_t arp;
    } __attribute__((packed)) pkt;

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth.h_dest, 0xFF, 6);
    memcpy(pkt.eth.h_source, local_mac, 6);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.hw_type = htons(1); // Ethernet
    pkt.arp.proto_type = htons(ETH_P_IP); // IPv4
    pkt.arp.hw_len = 6;
    pkt.arp.proto_len = 4;
    pkt.arp.op = htons(1); // ARP Request
    memcpy(pkt.arp.sender_mac, local_mac, 6);
    pkt.arp.sender_ip = local_ip;
    memset(pkt.arp.target_mac, 0x00, 6);

    int sent = 0;
    for (uint32_t ip = network + 1; ip < broadcast; ip++) {
        if (ip == hs_ip) continue; 
        uint32_t target_ip = htonl(ip);
        pkt.arp.target_ip = target_ip;
        
        sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sll, sizeof(sll));
        sent++;
        usleep(500); // 0.5ms delay
    }
    
    log_info("ARP Scanner: Sent %d ARP Requests. Waiting for replies (2 seconds)...", sent);

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    long long end_time = 2000; 
    uint8_t buffer[2048];
    while (end_time > 0) {
        int ret = poll(&pfd, 1, 100); 
        if (ret > 0 && (pfd.revents & POLLIN)) {
            int len = recv(fd, buffer, sizeof(buffer), 0);
            if (len >= (int)(sizeof(struct ethhdr) + sizeof(arp_header_t))) {
                struct ethhdr *eth = (struct ethhdr *)buffer;
                if (ntohs(eth->h_proto) == ETH_P_ARP) {
                    arp_header_t *arp = (arp_header_t *)(buffer + sizeof(struct ethhdr));
                    if (ntohs(arp->op) == 2) { // ARP Reply
                        if ((ntohl(arp->sender_ip) & hs_mask) == network) { 
                            arp_cache_add(arp->sender_ip, arp->sender_mac);
                        }
                    }
                }
            }
        }
        end_time -= 100;
    }

    close(fd);
    log_info("ARP Scanner: Finished scanning subnet.");
    return 0;
}
