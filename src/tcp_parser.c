#include "../inc/tcp_parser.h"
#include "../util/inc/logger.h"

void parse_tcp(const struct ip *ip_header, const u_char *packet) {
    // Calculate TCP header location:
    // packet + Ethernet header (14 bytes) + IP header length (variable, in 4-byte words)
    const u_char *tcp_start = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
    const struct tcphdr *tcp_header = (struct tcphdr *)tcp_start;

    // Convert IP addresses from network byte order to human-readable strings
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    log_message("[TCP] SrcIP=%s, SrcPort=%u, DstIP=%s, DstPort=%u, Protocol=TCP\n", 
            src_ip, ntohs(tcp_header->source), 
            dst_ip, ntohs(tcp_header->dest));
}
