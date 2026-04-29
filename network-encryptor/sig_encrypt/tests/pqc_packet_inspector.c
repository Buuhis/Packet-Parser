#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include "traffic_crypto.h"

// Màu sắc cho log
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KCYN  "\x1B[36m"

void hex_dump(const char* label, const uint8_t* data, size_t len) {
    printf("%s[%s] (%zu bytes):%s\n", KCYN, label, len, KNRM);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    printf("----------------------------------------------------------\n");
}

void print_packet_structure(const char* title, const uint8_t* pkt, size_t len, int is_encrypted) {
    struct iphdr *ip = (struct iphdr *)pkt;
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    printf("\n%s=== %s ===%s\n", KYEL, title, KNRM);
    printf("IP Header: Source=%s, Dest=%s, Proto=%d\n", inet_ntoa(src), inet_ntoa(dst), ip->protocol);

    if (!is_encrypted) {
        struct tcphdr *tcp = (struct tcphdr *)(pkt + (ip->ihl * 4));
        printf("TCP Header: SrcPort=%d, DstPort=%d, Seq=%u\n", ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq));
        printf("Payload Data: %s\n", (char*)(pkt + (ip->ihl * 4) + (tcp->doff * 4)));
    } else {
        printf("%s[ENCRYPTED SECTION]%s: TCP Header and Payload are now hidden ciphertext.\n", KRED, KNRM);
        // Dump a bit of the ciphertext
        hex_dump("Wire View (IP + Encrypted Blob)", pkt, len);
    }
}

void save_to_file(const char* filename, const uint8_t* data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("%s[FILE]%s Saved packet to %s\n", KGRN, KNRM, filename);
    } else {
        printf("%s[ERROR]%s Could not save to %s\n", KRED, KNRM, filename);
    }
}

int main() {
    printf("%sPQC L4 PACKET INSPECTOR - SD-WAN SIMULATION%s\n", KBLU, KNRM);
    
    // 1. Khoi tao thu vien PQC
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        printf("Failed to init PQC\n");
        return 1;
    }

    // 2. Tao khoa va nonce gia lap (tuong tu nhu sau Handshake)
    uint8_t key[32] __attribute__((aligned(64)));
    uint8_t nonce[12] __attribute__((aligned(64)));
    trf_pqc_generate_random_key(key, 32);
    trf_pqc_generate_nonce(nonce);

    // 3. Xay dung goi tin tho (IP + TCP + Data)
    uint8_t packet[1024];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 12);
    ip->id = htons(12345);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.10");
    ip->daddr = inet_addr("172.16.0.5");

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = htons(1234);
    tcp->dest = htons(80);
    tcp->seq = htonl(100);
    tcp->doff = 5; // 20 bytes

    char *payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
    strcpy(payload, "SECRET_DATA");

    size_t original_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload) + 1;
    
    print_packet_structure("ORIGINAL PACKET (LOCAL SIDE)", packet, original_len, 0);

    // 4. Mo phong TRICH XUAT AAD
    uint8_t aad[12];
    memcpy(aad, &ip->saddr, 4);
    memcpy(aad + 4, &ip->daddr, 4);
    memcpy(aad + 8, &tcp->source, 2);
    memcpy(aad + 10, &tcp->dest, 2);

    // 5. MA HOA L4
    int enc_len;
    uint8_t *crypto_ptr = packet + sizeof(struct iphdr);
    int data_to_encrypt_len = original_len - sizeof(struct iphdr);

    if (trf_encrypt_payload_gcm(key, nonce, 12, aad, 12, crypto_ptr, data_to_encrypt_len, &enc_len) == TRF_PQC_OK) {
        size_t wire_len = sizeof(struct iphdr) + enc_len;
        print_packet_structure("PACKET ON THE WIRE (ENCRYPTED L4)", packet, wire_len, 1);
        save_to_file("encrypted_packet.bin", packet, wire_len);

        // 6. GIAI MA (SITE NHAN)
        int dec_len;
        if (trf_decrypt_payload_gcm(key, nonce, 12, aad, 12, crypto_ptr, enc_len, &dec_len) == TRF_PQC_OK) {
            size_t restored_len = sizeof(struct iphdr) + dec_len;
            print_packet_structure("RESTORED PACKET (REMOTE SIDE)", packet, restored_len, 0);
            save_to_file("decrypted_packet.bin", packet, restored_len);
            printf("%s[SUCCESS] Packet integrity verified and data restored.%s\n", KGRN, KNRM);
        } else {
            printf("%s[FAIL] Decryption or Authentication failed!%s\n", KRED, KNRM);
        }
    }

    trf_pqc_cleanup();
    return 0;
}
