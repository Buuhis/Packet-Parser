#include "../inc/packet_parser.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    int link_type = *(int *)user;
    const u_char *ip_packet = NULL;

    // Handle different link-layer types
    if (link_type == DLT_EN10MB) {
        // Standard Ethernet frame processing
        struct ether_header *eth = (struct ether_header *)packet;
        
        // Check if this is an IPv4 packet (0x0800)
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            return; 
        
        // IP packet starts after the Ethernet header (14 bytes)
        ip_packet = packet + sizeof(struct ether_header);

    } else if (link_type == DLT_IEEE802_11_RADIO) {
        // Radiotap + 802.11 frame processing
        // Radiotap header length is stored in bytes 2-3 (little-endian)
        uint16_t radiotap_len = packet[2] | (packet[3] << 8);
        
        // Skip Radiotap header + basic 802.11 header (24 bytes)
        // Note: This is a simplified approach - real 802.11 headers can vary in length
        ip_packet = packet + radiotap_len + 24;
        
        // TODO: Refine 802.11 header parsing for variable-length headers

    } else if (link_type == DLT_IEEE802_11) {
        // 802.11 frame without Radiotap header
        // Skip basic 802.11 header (24 bytes) to reach IP packet
        ip_packet = packet + 24;

    } else {
        fprintf(stderr, "Unsupported link-layer: %d\n", link_type);
        return;
    }

    struct ip *ip_hdr = (struct ip *)ip_packet;
    if (ip_hdr->ip_v != 4) return;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        parse_tcp(ip_hdr, packet);
    } 
    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        parse_udp(ip_hdr, packet);
    }
}

