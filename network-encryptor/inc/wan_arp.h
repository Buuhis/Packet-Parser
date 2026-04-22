#ifndef WAN_ARP_H
#define WAN_ARP_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "config.h"
#include "interface.h"

#define ARP_CACHE_SIZE 2048
#define ARP_PERSIST_DIR "/var/lib/network-encryptor"

struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
    uint32_t last_seen_sec;
};

struct arp_cache {
    struct arp_entry entries[ARP_CACHE_SIZE];
    pthread_mutex_t lock;
    int raw_fd;
    int ifindex;
    char ifname[IF_NAMESIZE];
    uint8_t if_mac[6];
    uint32_t if_ip;
    uint32_t persist_dirty;
    volatile int *running_flag; 
};

int arp_cache_lookup(struct arp_cache *c, uint32_t ip, uint8_t mac_out[6]);
void arp_send_request(struct arp_cache *c, uint32_t target_ip);

int arp_init_for_local(struct arp_cache *c,
                         const struct xsk_interface *local_iface,
                         volatile int *running_flag);

void *arp_listener_thread(void *arg);


int wan_rewrite_dest_mac(struct arp_cache *wan_cache,
                          const struct wan_config *wan_cfg,
                          const struct xsk_interface *wan_iface,
                          uint8_t *pkt);


void wan_log_peer_mac(struct arp_cache *wan_cache,
                       const char *ifname,
                       const struct wan_config *wan_cfg);

#endif

