#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include "../inc/traffic_crypto.h"
#include "../inc/crypt.h"

#define BUFFER_SIZE 65535
#define TAG_SIZE_GCM 16

int main(int argc, char* argv[]) {
    if (argc < 8) {
        printf("Sử dụng:\n");
        printf("  Server 1 (Mã hóa: Nhận từ LAN, gửi ra WAN):\n");
        printf("    %s --encrypt <interface_LAN> <cổng_LAN> <interface_WAN> <ip_server_2_WAN> <cổng_server_2_WAN> <optimize: 0|1>\n", argv[0]);
        printf("  Server 2 (Giải mã: Nhận từ WAN, gửi ra LAN):\n");
        printf("    %s --decrypt <interface_WAN> <cổng_WAN> <interface_LAN> <ip_client_2_LAN> <cổng_client_2_LAN> <optimize: 0|1>\n", argv[0]);
        printf("\nLưu ý: Bạn cần chạy bằng quyền 'sudo' để sử dụng tùy chọn ràng buộc Interface vật lý (SO_BINDTODEVICE).\n");
        return 1;
    }

    const char* mode = argv[1];
    const char* listen_interface = argv[2];
    int listen_port = atoi(argv[3]);
    const char* send_interface = argv[4];
    const char* dest_ip = argv[5];
    int dest_port = atoi(argv[6]);
    int optimize = atoi(argv[7]);

    int is_encrypt = (strcmp(mode, "--encrypt") == 0);

    printf("====================================================\n");
    printf("   PQC DUAL-INTERFACE THROUGHPUT GATEWAY TEST TOOL\n");
    printf("====================================================\n");
    printf("  Chế độ          : %s\n", is_encrypt ? "MÃ HÓA (Server 1)" : "GIẢI MÃ (Server 2)");
    printf("  Interface Nhận  : %s (Cổng: %d)\n", listen_interface, listen_port);
    printf("  Interface Gửi   : %s\n", send_interface);
    printf("  Đích chuyển tiếp: %s:%d\n", dest_ip, dest_port);
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
    memset(session_key, 0x55, 32); // Khóa đối xứng giả lập cố định cho phiên test

    // 2. Thiết lập DUAL SOCKET (Một socket chuyên nhận, một socket chuyên gửi)
    // Việc tách socket giúp định tuyến vật lý chính xác trên Router đa cổng!
    
    // 2.1. SOCKET NHẬN (RX SOCKET) - Ràng buộc chặt vào Interface nhận vật lý
    int rx_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx_sock_fd < 0) {
        perror("Lỗi tạo RX Socket");
        return 1;
    }

    // Ràng buộc RX Socket vào Interface vật lý nhận bằng SO_BINDTODEVICE
    if (setsockopt(rx_sock_fd, SOL_SOCKET, SO_BINDTODEVICE, listen_interface, strlen(listen_interface)) < 0) {
        perror("Lỗi: Không thể ràng buộc RX Socket vào Interface nhận (Cần sudo?)");
        close(rx_sock_fd);
        return 1;
    }

    int sock_buf_size = 16 * 1024 * 1024; // 16MB buffer phòng tránh drop gói tin ở tốc độ cao
    setsockopt(rx_sock_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));

    struct sockaddr_in listen_addr, dest_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(rx_sock_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("Lỗi Bind RX socket");
        close(rx_sock_fd);
        return 1;
    }

    // 2.2. SOCKET GỬI (TX SOCKET) - Ràng buộc chặt vào Interface gửi vật lý
    int tx_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tx_sock_fd < 0) {
        perror("Lỗi tạo TX Socket");
        close(rx_sock_fd);
        return 1;
    }

    // Ràng buộc TX Socket vào Interface gửi vật lý bằng SO_BINDTODEVICE
    if (setsockopt(tx_sock_fd, SOL_SOCKET, SO_BINDTODEVICE, send_interface, strlen(send_interface)) < 0) {
        perror("Lỗi: Không thể ràng buộc TX Socket vào Interface gửi (Cần sudo?)");
        close(rx_sock_fd);
        close(tx_sock_fd);
        return 1;
    }
    setsockopt(tx_sock_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);

    // 3. Vòng lặp nhận và chuyển tiếp gói tin xuyên Interface
    uint8_t buffer[BUFFER_SIZE];
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint64_t packet_count = 0;
    uint64_t last_report_time = time(NULL);
    uint64_t total_bytes = 0;
    int is_first_packet = 1;

    printf("Hệ thống Dual-Interface đã sẵn sàng xử lý gói tin. Bắt đầu truyền traffic...\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        // Nhận gói tin từ RX socket (chỉ nhận traffic đi vào Interface chỉ định)
        ssize_t recv_len = recvfrom(rx_sock_fd, buffer, BUFFER_SIZE - TAG_SIZE_GCM, 0, 
                                    (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len <= 0) continue;

        packet_count++;
        total_bytes += recv_len;

        // Giả lập Nonce tăng dần cho mỗi packet
        nonce[0] = (uint8_t)(packet_count & 0xFF);
        nonce[1] = (uint8_t)((packet_count >> 8) & 0xFF);

        if (is_encrypt) {
            // ==========================================
            // CHẾ ĐỘ MÃ HÓA (SERVER 1: Nhận LAN -> Gửi WAN)
            // ==========================================
            int out_len = 0;
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
                
                scrypt_CipherUpdate(ctx, buffer, recv_len, buffer, &update_len);
                scrypt_CipherFinal(ctx, buffer + update_len, &final_len);

                uint8_t tag[TAG_SIZE_GCM];
                word32 tag_len = TAG_SIZE_GCM;
                scrypt_CipherGetTag(ctx, tag, &tag_len);
                
                memcpy(buffer + update_len + final_len, tag, TAG_SIZE_GCM);
                out_len = update_len + final_len + TAG_SIZE_GCM;

                // Gửi gói tin đã mã hóa qua TX socket (đẩy thẳng ra WAN)
                sendto(tx_sock_fd, buffer, out_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            }

        } else {
            // ==========================================
            // CHẾ ĐỘ GIẢI MÃ (SERVER 2: Nhận WAN -> Gửi LAN)
            // ==========================================
            if (recv_len > TAG_SIZE_GCM) {
                int payload_len = recv_len - TAG_SIZE_GCM;
                uint8_t tag[TAG_SIZE_GCM];
                memcpy(tag, buffer + payload_len, TAG_SIZE_GCM);

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
                    scrypt_CipherUpdate(ctx, buffer, payload_len, buffer, &update_len);
                    
                    if (scrypt_CipherFinal(ctx, buffer + update_len, &final_len) == 0) {
                        int orig_len = update_len + final_len;
                        // Gửi gói tin đã giải mã qua TX socket (đẩy thẳng ra LAN về phía Client 2)
                        sendto(tx_sock_fd, buffer, orig_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                    }
                }
            }
        }

        // Báo cáo định kỳ mỗi 5 giây
        uint64_t now = time(NULL);
        if (now - last_report_time >= 5) {
            double duration = now - last_report_time;
            double mbps = ((double)total_bytes * 8.0 / duration) / 1000000.0;
            printf("[Thống kê] %s -> %s | Đã xử lý: %lu gói | Băng thông WAN: %.2f Mbps\n", 
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
