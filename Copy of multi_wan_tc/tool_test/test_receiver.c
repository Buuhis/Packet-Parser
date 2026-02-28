#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define BUFFER_SIZE 65536

void parse_packet(unsigned char *buffer, int data_size) {
    if (data_size < (int)sizeof(struct ethhdr)) return;
    
    struct ethhdr *eth = (struct ethhdr *)buffer;
    uint16_t eth_type = ntohs(eth->h_proto);
    
    // 0x0800 là IPv4
    if (eth_type == ETH_P_IP) {
        if (data_size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;
        
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        // Bỏ qua các gói không phải ICMP (1) và UDP (17) để đỡ rối
        if (ip->protocol != IPPROTO_ICMP && ip->protocol != IPPROTO_UDP) return;
        
        struct sockaddr_in src, dst;
        memset(&src, 0, sizeof(src));
        memset(&dst, 0, sizeof(dst));
        
        src.sin_addr.s_addr = ip->saddr;
        dst.sin_addr.s_addr = ip->daddr;
        
        uint16_t tot_len = ntohs(ip->tot_len);
        uint16_t id = ntohs(ip->id);
        uint16_t frag_off = ntohs(ip->frag_off);
        
        int mf = (frag_off & IP_MF) != 0;
        int offset = (frag_off & IP_OFFMASK) * 8;
        
        const char *proto_name = (ip->protocol == IPPROTO_ICMP) ? "ICMP" : "UDP ";
        
        printf("[NHẬN] ID_IP: %5d | %15s -> %-15s | %s | Len(IP_Hdr+Payload): %4d | Có_Cờ_MF: %d | Vị_Trí_Mảnh(Offset): %4d\n",
               id, inet_ntoa(src.sin_addr), inet_ntoa(dst.sin_addr), proto_name,
               tot_len, mf, offset);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Cách dùng: sudo %s <tên_cổng_mạng_LAN>\n", argv[0]);
        exit(1);
    }

    const char *iface = argv[1];
    int sock;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Lỗi tạo raw socket, hãy nhớ chạy với quyền sudo");
        exit(1);
    }

    // Bind vào inteface chỉ định để tránh nhiễu
    int ifidx = if_nametoindex(iface);
    if (ifidx == 0) {
        perror("Không tìm thấy interface");
        exit(1);
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifidx;

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Lỗi bind socket");
        exit(1);
    }

    printf("[*] Đang lắng nghe bắt gói tin TRỰC TIẾP TỪ PHẦN CỨNG trên cổng mạng: %s ...\n", iface);

    while (1) {
        struct sockaddr saddr;
        int saddr_len = sizeof(saddr);
        
        int data_size = recvfrom(sock, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        if (data_size < 0) {
            perror("Lỗi recvfrom");
            break;
        }
        
        parse_packet(buffer, data_size);
    }

    close(sock);
    free(buffer);
    return 0;
}
