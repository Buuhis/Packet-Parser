#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <netinet/ip.h>             // IP header structure
#include <netinet/udp.h>            // UDP header structure
#include <netinet/if_ether.h>       // Ethernet header structure   
#include <arpa/inet.h>              // IP address conversion functions (inet_ntop, ntohl, htons,...)
#include <pcap.h>                   // pcap library for packet capture
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/**
 * @brief Parse DNS packet and extract detailed DNS information
 * 
 * This function takes IP header, UDP header, and the full packet as input
 * and is responsible for parsing the DNS payload inside the UDP packet.
 * 
 * It extracts and analyzes:
 * - DNS header fields (ID, flags, counts)
 * - DNS flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
 * - Query domain names
 * - Query types and classes
 * 
 * @param ip_header Pointer to the IP header structure
 * @param udp_header Pointer to the UDP header structure
 * @param packet Pointer to the complete packet data
 */
void parse_dns(const struct ip *ip_header, const struct udphdr *udp_header, const u_char *packet);

#endif // DNS_PARSER_H


