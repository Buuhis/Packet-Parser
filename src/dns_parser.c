#include "../inc/dns_parser.h"
#include "../util/inc/logger.h"

struct dns_header {
    uint16_t id;        // Query identifier (matches query with response)
    uint16_t flags;     // DNS flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;   // Number of questions in question section
    uint16_t ancount;   // Number of answers in answer section
    uint16_t nscount;   // Number of authority records in authority section
    uint16_t arcount;   // Number of additional records in additional section
}__attribute__((packed));

void parse_dns(const struct ip *ip_hdr, const struct udphdr *udp_hdr, const u_char *packet) {
    // Calculate DNS payload start location:
    // packet + Ethernet header + IP header + UDP header
    const u_char *dns_start = packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr);
    struct dns_header *dns = (struct dns_header *)dns_start;

    // Extract DNS header fields (convert from network to host byte order)
    uint16_t id = ntohs(dns->id);
    uint16_t flags = ntohs(dns->flags);

    // Parse DNS flags by bit manipulation (RFC 1035)
    int qr     = (flags >> 15) & 0x1;    // Query (0) or Response (1)
    int opcode = (flags >> 11) & 0xF;    // Operation code (0=Standard Query, 1=Inverse Query, etc.)
    int aa     = (flags >> 10) & 0x1;    // Authoritative Answer
    int tc     = (flags >> 9)  & 0x1;    // Truncation (response too long for UDP)
    int rd     = (flags >> 8)  & 0x1;    // Recursion Desired
    int ra     = (flags >> 7)  & 0x1;    // Recursion Available
    int z      = (flags >> 4)  & 0x7;    // Reserved field (must be 0)
    int rcode  = (flags >> 0)  & 0xF;    // Response code (0=No Error, 3=NXDOMAIN, etc.)

    // Extract record counts from DNS header
    uint16_t qdcount = ntohs(dns->qdcount);  // Number of questions
    uint16_t ancount = ntohs(dns->ancount);  // Number of answers
    uint16_t nscount = ntohs(dns->nscount);  // Number of authority records
    uint16_t arcount = ntohs(dns->arcount);  // Number of additional records

    // Parse domain name from question section
    // DNS names use length-prefixed labels (e.g., 3www3com0)
    const u_char *qname = dns_start + sizeof(struct dns_header);
    char domain[256];
    int pos = 0;
    
    // Extract domain name labels until we hit a null byte (end of name)
    while (*qname != 0 && pos < sizeof(domain) - 1) {
        int len = *qname++;  // Get length of next label
        
        // Copy label characters, replacing non-printable chars with dots
        for (int i = 0; i < len; i++) {
            if (isprint(*qname))
                domain[pos++] = *qname;
            else
                domain[pos++] = '.';
            qname++;
        }
        
        // Add dot separator between labels (except after last label)
        if (*qname != 0) domain[pos++] = '.';
    }
    domain[pos] = '\0';
    qname++; // Skip null byte

    // Extract query type and class (both are 16-bit values in network byte order)
    uint16_t qtype = ntohs(*(uint16_t *)qname);   // Query type (1=A, 28=AAAA, 65=HTTPS, etc.)
    qname += 2;  // Move pointer past query type
    uint16_t qclass = ntohs(*(uint16_t *)qname);  // Query class (1=IN for Internet)

    log_message("[DNS] ID=0x%04x, QR=%d, Opcode=%d, AA=%d, TC=%d, RD=%d, RA=%d, Z=%d, RCODE=%d, "
           "QDCOUNT=%u, ANCOUNT=%u, NSCOUNT=%u, ARCOUNT=%u, Query=%s, Type=%u, Class=%u\n",
           id, qr, opcode, aa, tc, rd, ra, z, rcode,
           qdcount, ancount, nscount, arcount, domain, qtype, qclass);
}

