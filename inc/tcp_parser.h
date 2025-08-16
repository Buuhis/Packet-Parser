#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <stdio.h>

// Network protocol header structures
#include <netinet/tcp.h>        // TCP header structure
#include <netinet/ip.h>          // IP header structure
#include <netinet/if_ether.h>    // Ethernet header structure

// Network address conversion utilities
#include <arpa/inet.h>

/**
 * @brief Parse TCP packet and extract relevant information
 * 
 * This function analyzes a TCP packet and logs the following information:
 * - Source and destination IP addresses
 * - Source and destination TCP ports
 * - Protocol type (TCP)
 * 
 * The function assumes the packet contains an Ethernet frame with an IP packet
 * containing a TCP segment.
 * 
 * @param ip_header Pointer to the IP header structure
 * @param packet Pointer to the complete packet data (starting from Ethernet header)
 */
void parse_tcp(const struct ip *ip_header, const u_char *packet);

#endif // TCP_PARSER_H
