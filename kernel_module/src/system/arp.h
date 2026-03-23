#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <arpa/inet.h>

/* Initialize the ARP cache */
void arp_cache_init(void);

/* Search for MAC address by IPv4 address (Network byte order). Returns 0 on success, -1 on miss */
int arp_cache_lookup(uint32_t ip, uint8_t mac_out[6]);

/* Add an entry to the ARP cache */
void arp_cache_add(uint32_t ip, const uint8_t mac[6]);

/* 
 * Broadcast ARP requests to the entire subnet on the given interface.
 * local_ip and netmask are in Network Byte Order.
 * Listens for replies and populates the ARP cache.
 */
int arp_scanner_scan_subnet(const char *ifname, uint32_t local_ip, uint32_t netmask, const uint8_t local_mac[6]);

#endif /* ARP_H */
