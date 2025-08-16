#include "../inc/udp_parser.h"
#include "../inc/dns_parser.h"
#include "../util/inc/logger.h"

void parse_udp(const struct ip *ip_header, const u_char *packet) {
    // Calculate UDP header location:
    // packet + Ethernet header (14 bytes) + IP header length (variable, in 4-byte words)
    const u_char *udp_start = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
    const struct udphdr *udp_header = (struct udphdr *)udp_start;

    // Convert IP addresses from network byte order to human-readable strings
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    log_message("[UDP] SrcIP=%s, SrcPort=%u, DstIP=%s, DstPort=%u, Protocol=UDP\n", 
            src_ip, ntohs(udp_header->source), 
            dst_ip, ntohs(udp_header->dest));

    // Detect DNS traffic by checking if either source or destination port is 53
    // Port 53 is the standard DNS port for queries and responses
    if (ntohs(udp_header->uh_sport) == 53 || ntohs(udp_header->uh_dport) == 53) {
        parse_dns(ip_header, udp_header, packet);
    }
}
