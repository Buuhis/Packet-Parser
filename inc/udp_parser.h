#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include <stdio.h>

// Network protocol header structures
#include <netinet/udp.h>        // UDP header structure
#include <netinet/ip.h>          // IP header structure
#include <netinet/if_ether.h>    // Ethernet header structure

// Network address conversion utilities
#include <arpa/inet.h>

/**
 * @brief Parse UDP packet and extract relevant information
 * 
 * This function analyzes a UDP packet and:
 * 1. Logs basic UDP packet information (IPs, ports, protocol)
 * 2. Detects DNS traffic (port 53) and routes to DNS parser
 * 3. Assumes Ethernet frame with IP packet containing UDP datagram
 * 
 * @param ip_header Pointer to the IP header structure
 * @param packet Pointer to the complete packet data (starting from Ethernet header)
 */
void parse_udp(const struct ip *ip_header, const u_char *packet);

#endif // UDP_PARSER_H
