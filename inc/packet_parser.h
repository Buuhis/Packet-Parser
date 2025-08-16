/**
 * @file packet_parser.h
 * @brief Main packet parsing interface for network packet analysis
 * 
 * This header file defines the main packet handler function that processes
 * incoming network packets and routes them to appropriate protocol parsers.
 * It supports multiple link-layer types including Ethernet, 802.11, and Radiotap.
 * 
 * @author  To Hoang Buu
 * @version 1.0
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Network packet capture library
#include <pcap.h>

// Network protocol headers
#include <netinet/if_ether.h>  // Ethernet header structures
#include <netinet/ip.h>         // IP header structures
#include <netinet/tcp.h>        // TCP header structures
#include <netinet/udp.h>        // UDP header structures

// Network address conversion utilities
#include <arpa/inet.h>

// Protocol-specific parser headers
#include "tcp_parser.h"
#include "udp_parser.h"

/**
 * @brief Main packet handler function for processing captured network packets
 * 
 * This function is called by libpcap for each captured packet. It:
 * 1. Determines the link-layer type (Ethernet, 802.11, Radiotap)
 * 2. Extracts the IP packet from the link-layer frame
 * 3. Routes the packet to appropriate protocol parsers (TCP/UDP)
 * 4. Filters for IPv4 packets only
 * 
 * @param user Pointer to user data (link-layer type in this case)
 * @param header Packet header containing metadata (timestamp, length, etc.)
 * @param packet Pointer to the actual packet data
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

#endif // PACKET_PARSER_H
