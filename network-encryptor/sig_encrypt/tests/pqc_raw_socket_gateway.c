#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include "../inc/traffic_crypto.h"
#include "../inc/crypt.h"

#define BUFFER_SIZE 65535
#define TAG_SIZE_GCM 16

// Hàm tính toán checksum IP đơn giản
unsigned short calculate_ip_checksum(unsigned short *addr, int count) {
    register long sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

int main(int argc, char* argv[]) {
    if (argc < 7) {
        printf("Sử dụng:\n");
        printf("  Server 1 (Mã hóa: Captures from LAN interface, encrypts, sends out to WAN):\n");
        printf("    %s --encrypt <interface_LAN> <interface_WAN> <cổng_nghe> <MAC_đích_Server2_WAN> <optimize: 0|1>\n", argv[0]);
        printf("  Server 2 (Giải mã: Captures from WAN interface, decrypts, sends out to LAN):\n");
        printf("    %s --decrypt <interface_WAN> <interface_LAN> <cổng_nghe> <MAC_đích_Client2_LAN> <optimize: 0|1>\n", argv[0]);
        printf("\nLưu ý: Bắt buộc chạy bằng quyền 'sudo' (yêu cầu quyền Raw Socket).\n");
        return 1;
    }

    const char* mode = argv[1];
    const char* listen_interface = argv[2];
    const char* send_interface = argv[3];
    int listen_port = atoi(argv[4]);
    const char* dest_mac_str = argv[5];
    int optimize = atoi(argv[6]);

    int is_encrypt = (strcmp(mode, "--encrypt") == 0);

    // Chuyển đổi chuỗi MAC đích thành mảng byte
    uint8_t dest_mac[6];
    struct ether_addr *eth_addr = ether_aton(dest_mac_str);
    if (!eth_addr) {
        fprintf(stderr, "Lỗi: Định dạng MAC không hợp lệ! (Ví dụ: 00:11:22:33:44:55)\n");
        return 1;
    }
    memcpy(dest_mac, eth_addr->ether_addr_octet, 6);

    printf("====================================================\n");
    printf("   PQC STANDALONE L2 RAW SOCKET GATEWAY BENCHMARK\n");
    printf("====================================================\n");
    printf("  Chế độ          : %s\n", is_encrypt ? "MÃ HÓA (Server 1)" : "GIẢI MÃ (Server 2)");
    printf("  Cổng bắt gói    : UDP %d (Bypass Kernel IP Forward)\n", listen_port);
    printf("  Card Nhận (In)  : %s\n", listen_interface);
    printf("  Card Gửi (Out)  : %s\n", send_interface);
    printf("  MAC Đích Chuyển : %s\n", dest_mac_str);
    printf("  Tối ưu hóa      : %s\n", optimize ? "KÍCH HOẠT (key=NULL)" : "TẮT (Full Init per packet)");
    printf("====================================================\n\n");

    // 1. Khởi tạo PQC Engine
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "Lỗi: Không thể khởi tạo PQC Global!\n");
        return 1;
    }

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) {
        fprintf(stderr, "Lỗi: Không thể tạo SCryptCipherCtx!\n");
        return 1;
    }

    uint8_t session_key[32];
    memset(session_key, 0x55, 32); // Khóa đối xứng giả lập

    // 2. Lấy thông tin Interface ID & MAC nguồn của Card Gửi
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr_mac, ifr_idx;
    
    strncpy(ifr_mac.ifr_name, send_interface, IFNAMSIZ - 1);
    if (ioctl(temp_sock, SIOCGIFHWADDR, &ifr_mac) < 0) {
        perror("Lỗi lấy MAC của interface gửi");
        close(temp_sock);
        return 1;
    }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr_mac.ifr_hwaddr.sa_data, 6);

    strncpy(ifr_idx.ifr_name, send_interface, IFNAMSIZ - 1);
    if (ioctl(temp_sock, SIOCGIFINDEX, &ifr_idx) < 0) {
        perror("Lỗi lấy index của interface gửi");
        close(temp_sock);
        return 1;
    }
    int send_ifindex = ifr_idx.ifr_ifindex;
    close(temp_sock);

    // 3. Khởi tạo L2 RAW SOCKET
    // L2 Socket (ETH_P_IP) giúp chúng ta chụp được gói tin IPv4 nguyên bản bao gồm cả Ethernet Header
    // trước khi kernel IP forwarding / routing table kịp can thiệp!
    int rx_sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (rx_sock_fd < 0) {
        perror("Lỗi tạo RAW Socket Nhận");
        return 1;
    }

    struct sockaddr_ll sll_rx;
    memset(&sll_rx, 0, sizeof(sll_rx));
    sll_rx.sll_family = AF_PACKET;
    sll_rx.sll_ifindex = if_nametoindex(listen_interface);
    sll_rx.sll_protocol = htons(ETH_P_IP);

    if (bind(rx_sock_fd, (struct sockaddr*)&sll_rx, sizeof(sll_rx)) < 0) {
        perror("Lỗi Bind RAW socket nhận");
        close(rx_sock_fd);
        return 1;
    }

    // RAW Socket Gửi
    int tx_sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx_sock_fd < 0) {
        perror("Lỗi tạo RAW Socket Gửi");
        close(rx_sock_fd);
        return 1;
    }

    struct sockaddr_ll sll_tx;
    memset(&sll_tx, 0, sizeof(sll_tx));
    sll_tx.sll_family = AF_PACKET;
    sll_tx.sll_ifindex = send_ifindex;
    sll_tx.sll_protocol = htons(ETH_P_ALL);

    // 4. Vòng lặp capture và mã hóa/giải mã ở Layer 2
    uint8_t packet[BUFFER_SIZE];
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint64_t packet_count = 0;
    uint64_t last_report_time = time(NULL);
    uint64_t total_bytes = 0;
    int is_first_packet = 1;

    printf("Hệ thống L2 RAW Socket đã khởi động. Đang bắt các gói tin UDP trên cổng %d...\n\n", listen_port);

    while (1) {
        ssize_t pkt_len = recv(rx_sock_fd, packet, BUFFER_SIZE, 0);
        if (pkt_len <= 0) continue;

        // Phân tích Ethernet Header
        struct ethhdr *eth = (struct ethhdr *)packet;
        
        // Phân tích IP Header
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
        if (iph->protocol != IPPROTO_UDP) continue;

        // Phân tích UDP Header
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ethhdr) + (iph->ihl * 4));
        uint16_t dport = ntohs(udph->dest);

        // Chỉ xử lý các gói tin iperf3 / UDP đi vào cổng chỉ định
        if (dport != listen_port) continue;

        packet_count++;
        total_bytes += pkt_len;

        // Giả lập Nonce duy nhất cho mỗi packet
        nonce[0] = (uint8_t)(packet_count & 0xFF);
        nonce[1] = (uint8_t)((packet_count >> 8) & 0xFF);

        // Lấy con trỏ đến vùng dữ liệu UDP Payload
        uint8_t *payload = (uint8_t *)udph + sizeof(struct udphdr);
        int payload_len = ntohs(udph->len) - sizeof(struct udphdr);

        if (is_encrypt) {
            // ==========================================
            // CHẾ ĐỘ MÃ HÓA (SERVER 1: Nhận LAN -> Mã hóa -> Gửi WAN)
            // ==========================================
            int ret;
            if (optimize) {
                if (is_first_packet) {
                    ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, session_key, 32, nonce, 12, SCRYPT_ENCRYPTION);
                    is_first_packet = 0;
                } else {
                    ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, NULL, 0, nonce, 12, SCRYPT_ENCRYPTION);
                }
            } else {
                ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, session_key, 32, nonce, 12, SCRYPT_ENCRYPTION);
            }

            if (ret == 0) {
                scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);
                word32 update_len = 0, final_len = 0;
                
                scrypt_CipherUpdate(ctx, payload, payload_len, payload, &update_len);
                scrypt_CipherFinal(ctx, payload + update_len, &final_len);

                uint8_t tag[TAG_SIZE_GCM];
                word32 tag_len = TAG_SIZE_GCM;
                scrypt_CipherGetTag(ctx, tag, &tag_len);
                
                memcpy(payload + update_len + final_len, tag, TAG_SIZE_GCM);
                int new_payload_len = update_len + final_len + TAG_SIZE_GCM;

                // Cập nhật lại các Header
                udph->len = htons(new_payload_len + sizeof(struct udphdr));
                udph->check = 0; // Tắt checksum UDP (tăng tốc độ xử lý mạng)

                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + new_payload_len);
                iph->check = 0;
                iph->check = calculate_ip_checksum((unsigned short *)iph, iph->ihl * 4);

                // Cập nhật lại Ethernet Header (Thay đổi MAC nguồn & MAC đích để định tuyến ở L2)
                memcpy(eth->h_source, src_mac, 6);
                memcpy(eth->h_dest, dest_mac, 6);

                int final_pkt_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + new_payload_len;
                sendto(tx_sock_fd, packet, final_pkt_len, 0, (struct sockaddr*)&sll_tx, sizeof(sll_tx));
            }

        } else {
            // ==========================================
            // CHẾ ĐỘ GIẢI MÃ (SERVER 2: Nhận WAN -> Giải mã -> Gửi LAN)
            // ==========================================
            if (payload_len > TAG_SIZE_GCM) {
                int cipher_len = payload_len - TAG_SIZE_GCM;
                uint8_t tag[TAG_SIZE_GCM];
                memcpy(tag, payload + cipher_len, TAG_SIZE_GCM);

                int ret;
                if (optimize) {
                    if (is_first_packet) {
                        ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, session_key, 32, nonce, 12, SCRYPT_DECRYPTION);
                        is_first_packet = 0;
                    } else {
                        ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, NULL, 0, nonce, 12, SCRYPT_DECRYPTION);
                    }
                } else {
                    ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, session_key, 32, nonce, 12, SCRYPT_DECRYPTION);
                }

                if (ret == 0) {
                    scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);
                    scrypt_CipherSetTag(ctx, tag, TAG_SIZE_GCM);

                    word32 update_len = 0, final_len = 0;
                    scrypt_CipherUpdate(ctx, payload, cipher_len, payload, &update_len);
                    
                    if (scrypt_CipherFinal(ctx, payload + update_len, &final_len) == 0) {
                        int orig_payload_len = update_len + final_len;

                        // Cập nhật lại các Header
                        udph->len = htons(orig_payload_len + sizeof(struct udphdr));
                        udph->check = 0;

                        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + orig_payload_len);
                        iph->check = 0;
                        iph->check = calculate_ip_checksum((unsigned short *)iph, iph->ihl * 4);

                        // Cập nhật lại Ethernet Header sang MAC của Client 2
                        memcpy(eth->h_source, src_mac, 6);
                        memcpy(eth->h_dest, dest_mac, 6);

                        int final_pkt_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + orig_payload_len;
                        sendto(tx_sock_fd, packet, final_pkt_len, 0, (struct sockaddr*)&sll_tx, sizeof(sll_tx));
                    }
                }
            }
        }

        // Báo cáo định kỳ mỗi 5 giây
        uint64_t now = time(NULL);
        if (now - last_report_time >= 5) {
            double duration = now - last_report_time;
            double mbps = ((double)total_bytes * 8.0 / duration) / 1000000.0;
            printf("[L2 RAW] %s -> %s | Đã xử lý: %lu gói | Băng thông thực tế: %.2f Mbps\n", 
                   listen_interface, send_interface, packet_count, mbps);
            total_bytes = 0;
            last_report_time = now;
        }
    }

    close(rx_sock_fd);
    close(tx_sock_fd);
    scrypt_CipherCtxFree(ctx);
    trf_pqc_cleanup();
    return 0;
}
