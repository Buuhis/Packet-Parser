#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include "../inc/traffic_crypto.h"
#include "../inc/crypt.h"

#define BUFFER_SIZE 65535
#define TAG_SIZE_GCM 16

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printf("Sử dụng:\n");
        printf("  Server 1 (Mã hóa):\n");
        printf("    %s --encrypt <cổng_nghe> <ip_server_2> <cổng_server_2> <optimize: 0|1>\n", argv[0]);
        printf("  Server 2 (Giải mã):\n");
        printf("    %s --decrypt <cổng_nghe> <ip_client_2> <cổng_client_2> <optimize: 0|1>\n", argv[0]);
        return 1;
    }

    const char* mode = argv[1];
    int listen_port = atoi(argv[2]);
    const char* dest_ip = argv[3];
    int dest_port = atoi(argv[4]);
    int optimize = atoi(argv[5]);

    int is_encrypt = (strcmp(mode, "--encrypt") == 0);

    printf("====================================================\n");
    printf("   PQC STANDALONE THROUGHPUT GATEWAY TEST TOOL\n");
    printf("====================================================\n");
    printf("  Chế độ     : %s\n", is_encrypt ? "MÃ HÓA (Server 1)" : "GIẢI MÃ (Server 2)");
    printf("  Cổng nghe  : %d\n", listen_port);
    printf("  Đích chuyển: %s:%d\n", dest_ip, dest_port);
    printf("  Tối ưu hóa : %s\n", optimize ? "KÍCH HOẠT (key=NULL)" : "TẮT (Full Init per packet)");
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

    // Khóa đối xứng cố định cho phiên test (32 bytes)
    uint8_t session_key[32];
    memset(session_key, 0x55, 32);

    // 2. Thiết lập socket UDP
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Lỗi tạo Socket");
        return 1;
    }

    // Tăng kích thước bộ đệm socket để tránh drop gói tin ở tốc độ cao
    int sock_buf_size = 16 * 1024 * 1024; // 16MB
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));

    struct sockaddr_in listen_addr, dest_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(sock_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("Lỗi Bind socket");
        close(sock_fd);
        return 1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);

    // 3. Vòng lặp nhận và chuyển tiếp gói tin (Data Plane Loop)
    uint8_t buffer[BUFFER_SIZE];
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint64_t packet_count = 0;
    uint64_t last_report_time = time(NULL);
    uint64_t total_bytes = 0;
    int is_first_packet = 1;

    printf("Hệ thống đã sẵn sàng xử lý gói tin. Bắt đầu truyền traffic...\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        // Nhận gói tin từ Client hoặc Server liền trước
        ssize_t recv_len = recvfrom(sock_fd, buffer, BUFFER_SIZE - TAG_SIZE_GCM, 0, 
                                    (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len <= 0) continue;

        packet_count++;
        total_bytes += recv_len;

        // Giả lập Nonce duy nhất tăng dần cho mỗi packet để chống replay attack
        nonce[0] = (uint8_t)(packet_count & 0xFF);
        nonce[1] = (uint8_t)((packet_count >> 8) & 0xFF);

        if (is_encrypt) {
            // ==========================================
            // CHẾ ĐỘ MÃ HÓA (SERVER 1)
            // ==========================================
            int out_len = 0;
            int ret;

            if (optimize) {
                // Tối ưu hóa: Gói đầu tiên Init đầy đủ Key, các gói sau dùng key=NULL
                if (is_first_packet) {
                    ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, session_key, 32, nonce, 12, SCRYPT_ENCRYPTION);
                    is_first_packet = 0;
                } else {
                    ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, NULL, 0, nonce, 12, SCRYPT_ENCRYPTION);
                }
            } else {
                // Không tối ưu: Gọi đầy đủ Key Expansion trên từng gói tin
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

                // Gửi gói tin đã mã hóa sang Server 2
                sendto(sock_fd, buffer, out_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            }

        } else {
            // ==========================================
            // CHẾ ĐỘ GIẢI MÃ (SERVER 2)
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
                    
                    // Hàm final sẽ xác thực tính toàn vẹn của gói tin mã hóa
                    if (scrypt_CipherFinal(ctx, buffer + update_len, &final_len) == 0) {
                        int orig_len = update_len + final_len;
                        // Chuyển tiếp gói tin gốc (đã giải mã) sang Client 2
                        sendto(sock_fd, buffer, orig_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                    }
                }
            }
        }

        // Báo cáo thống kê nội bộ mỗi 5 giây
        uint64_t now = time(NULL);
        if (now - last_report_time >= 5) {
            double duration = now - last_report_time;
            double mbps = ((double)total_bytes * 8.0 / duration) / 1000000.0;
            printf("[Thống kê] Đã xử lý: %lu gói tin | Băng thông tức thời: %.2f Mbps\n", packet_count, mbps);
            total_bytes = 0;
            last_report_time = now;
        }
    }

    close(sock_fd);
    scrypt_CipherCtxFree(ctx);
    trf_pqc_cleanup();
    return 0;
}
