#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 60000

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Cách dùng: %s <IP_Client2>\n", argv[0]);
        exit(1);
    }

    const char *target_ip = argv[1];
    int sock;
    struct sockaddr_in dest_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Lỗi tạo socket");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, target_ip, &dest_addr.sin_addr) <= 0) {
        perror("Lỗi địa chỉ IP");
        exit(1);
    }

    int sizes[] = {100, 1400, 2000, 3000};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    printf("[*] Bắt đầu gửi gói tin thử nghiệm tới %s:%d...\n", target_ip, PORT);

    int seq = 1;
    for (int i = 0; i < num_sizes; i++) {
        int size = sizes[i];
        printf("\n[+] Đang gửi packet SEQ=%d với kích thước %d bytes UDP payload...\n", seq, size);
        
        char *payload = (char *)malloc(size);
        if (!payload) {
            perror("Lỗi cấp phát bộ nhớ");
            exit(1);
        }

        memset(payload, 'A', size);
        int header_len = snprintf(payload, size, "=== SEQ:%d | SIZE:%d ===", seq, size);
        if (header_len < size) {
            payload[header_len] = 'A'; // Khôi phục ký tự bị snprintf ghi đè bằng null terminator
        }

        if (sendto(sock, payload, size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("Lỗi gửi gói tin");
        } else {
            printf("    -> Đã gửi!\n");
        }

        free(payload);
        seq++;
        sleep(1);
    }

    close(sock);
    return 0;
}
