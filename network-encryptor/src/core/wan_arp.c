#include "../../inc/wan_arp.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>

static int mac_is_nonzero6(const uint8_t mac[6]) {
    return mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5];
}

static void pin_self_to_core0(void) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int get_iface_mac_and_ip(const char *ifname, uint8_t mac_out[6], uint32_t *ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifname);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    memcpy(mac_out, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip_out = sin->sin_addr.s_addr;

    close(fd);
    return 0;
}

static uint32_t arp_hash(uint32_t ip) {
    uint32_t x = ip;
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

int arp_cache_lookup(struct arp_cache *c, uint32_t ip, uint8_t mac_out[6]) {
    if (!c) return 0;
    uint32_t h = arp_hash(ip);
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        uint32_t idx = (h + i) & (ARP_CACHE_SIZE - 1);
        if (c->entries[idx].ip == 0) break;
        if (c->entries[idx].ip == ip) {
            memcpy(mac_out, c->entries[idx].mac, 6);
            pthread_mutex_unlock(&c->lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return 0;
}

static void arp_cache_insert(struct arp_cache *c, uint32_t ip, const uint8_t mac[6]) {
    if (!c) return;
    uint32_t h = arp_hash(ip);
    uint32_t now = (uint32_t)time(NULL);
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        uint32_t idx = (h + i) & (ARP_CACHE_SIZE - 1);
        if (c->entries[idx].ip == 0 || c->entries[idx].ip == ip) {
            c->entries[idx].ip = ip;
            memcpy(c->entries[idx].mac, mac, 6);
            c->entries[idx].last_seen_sec = now;
            c->persist_dirty = 1;
            break;
        }
    }
    pthread_mutex_unlock(&c->lock);
}

static void arp_cache_persist_path(const char *ifname, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/arp_%s.txt", ARP_PERSIST_DIR, ifname);
}

static void arp_cache_load(struct arp_cache *c) {
    char path[256];
    arp_cache_persist_path(c->ifname, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;

    uint32_t ip_host;
    unsigned int b0, b1, b2, b3, b4, b5;
    while (fscanf(f, "%u %x:%x:%x:%x:%x:%x\n",
                  &ip_host, &b0, &b1, &b2, &b3, &b4, &b5) == 7) {
        uint32_t ip = htonl(ip_host);
        uint8_t mac[6] = {(uint8_t)b0,(uint8_t)b1,(uint8_t)b2,(uint8_t)b3,(uint8_t)b4,(uint8_t)b5};
        arp_cache_insert(c, ip, mac);
    }
    fclose(f);
    c->persist_dirty = 0;
}

static void arp_cache_save(struct arp_cache *c) {
    if (!c || !c->persist_dirty) return;

    (void)mkdir(ARP_PERSIST_DIR, 0755);

    char path[256];
    arp_cache_persist_path(c->ifname, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return;

    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        if (c->entries[i].ip == 0) continue;
        uint32_t ip_host = ntohl(c->entries[i].ip);
        fprintf(f, "%u %02x:%02x:%02x:%02x:%02x:%02x\n",
                ip_host,
                c->entries[i].mac[0], c->entries[i].mac[1], c->entries[i].mac[2],
                c->entries[i].mac[3], c->entries[i].mac[4], c->entries[i].mac[5]);
    }
    c->persist_dirty = 0;
    pthread_mutex_unlock(&c->lock);
    fclose(f);
}

void arp_send_request(struct arp_cache *c, uint32_t target_ip) {
    if (!c) return;
    if (c->raw_fd < 0 || c->ifindex <= 0 || !mac_is_nonzero6(c->if_mac) || c->if_ip == 0)
        return;

    uint8_t frame[42];
    struct ether_header *eth = (struct ether_header *)frame;
    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, c->if_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(frame + sizeof(struct ether_header));
    memset(arp, 0, sizeof(*arp));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, c->if_mac, 6);
    memcpy(arp->arp_spa, &c->if_ip, 4);
    memset(arp->arp_tha, 0x00, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = c->ifindex;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);

    (void)sendto(c->raw_fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll));
}

void *arp_listener_thread(void *arg) {
    struct arp_cache *c = (struct arp_cache *)arg;
    uint8_t buf[2048];

    pin_self_to_core0();

    uint32_t last_save = (uint32_t)time(NULL);
    while (c && (!c->running_flag || *c->running_flag)) {
        ssize_t n = recv(c->raw_fd, buf, sizeof(buf), 0);
        if (n < (ssize_t)(sizeof(struct ether_header) + sizeof(struct ether_arp)))
            continue;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETH_P_ARP)
            continue;

        struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY)
            continue;

        uint32_t spa;
        memcpy(&spa, arp->arp_spa, 4);
        uint8_t mac[6];
        memcpy(mac, arp->arp_sha, 6);
        if (!mac_is_nonzero6(mac))
            continue;

        arp_cache_insert(c, spa, mac);

        uint32_t now = (uint32_t)time(NULL);
        if (now - last_save >= 2) {
            arp_cache_save(c);
            last_save = now;
        }
    }

    arp_cache_save(c);
    return NULL;
}

int arp_init_for_local(struct arp_cache *c,
                        const struct xsk_interface *local_iface,
                        volatile int *running_flag) {
    if (!c || !local_iface) return -1;

    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    c->raw_fd = -1;
    c->ifindex = local_iface->ifindex;
    strncpy(c->ifname, local_iface->ifname, IF_NAMESIZE - 1);
    c->ifname[IF_NAMESIZE - 1] = '\0';
    c->running_flag = running_flag;

    if (get_iface_mac_and_ip(c->ifname, c->if_mac, &c->if_ip) != 0) {
        fprintf(stderr, "[ARP] cannot read MAC/IP for %s\n", c->ifname);
        return -1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        fprintf(stderr, "[ARP] cannot open raw socket for %s\n", c->ifname);
        return -1;
    }
    c->raw_fd = fd;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = c->ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        fprintf(stderr, "[ARP] bind failed for %s\n", c->ifname);
        close(fd);
        c->raw_fd = -1;
        return -1;
    }

    arp_cache_load(c);
    return 0;
}

int wan_rewrite_dest_mac(struct arp_cache *wan_cache,
                          const struct wan_config *wan_cfg,
                          const struct xsk_interface *wan_iface,
                          uint8_t *pkt) {
    if (!wan_cache || !wan_cfg || !wan_iface || !pkt)
        return -1;


    if (wan_cfg->dst_ip != 0) {
        uint8_t dst_mac[6];
        if (arp_cache_lookup(wan_cache, wan_cfg->dst_ip, dst_mac)) {
            memcpy(pkt, dst_mac, 6);
            memcpy(pkt + 6, wan_cache->if_mac, 6);
            return 0;
        }
        arp_send_request(wan_cache, wan_cfg->dst_ip);
        return -1;
    }


    memcpy(pkt, wan_iface->dst_mac, 6);
    memcpy(pkt + 6, wan_iface->src_mac, 6);
    return 0;
}

void wan_log_peer_mac(struct arp_cache *wan_cache,
                       const char *ifname,
                       const struct wan_config *wan_cfg) {
    if (!wan_cache || !ifname || !wan_cfg)
        return;
    if (wan_cfg->dst_ip == 0)
        return;

    char ipbuf[INET_ADDRSTRLEN] = {0};
    struct in_addr a = { .s_addr = wan_cfg->dst_ip };
    inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));

    uint8_t mac[6];
    for (int tries = 0; tries < 10; tries++) {
        if (arp_cache_lookup(wan_cache, wan_cfg->dst_ip, mac)) {
            fprintf(stderr,
                    "[WAN ARP] if=%s local_ip=%u peer_ip=%s dest_mac=%02x:%02x:%02x:%02x:%02x:%02x (Sep device)\n",
                    ifname,
                    (unsigned)ntohl(wan_cache->if_ip),
                    ipbuf,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
        arp_send_request(wan_cache, wan_cfg->dst_ip);
        usleep(100000);
    }
    fprintf(stderr,
            "[WAN ARP] if=%s local_ip=%u peer_ip=%s dest_mac=UNRESOLVED (Sep / dst_ip not on L2 segment?)\n",
            ifname,
            (unsigned)ntohl(wan_cache->if_ip),
            ipbuf);
}

