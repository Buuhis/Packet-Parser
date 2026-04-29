#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include "traffic_crypto.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KCYN  "\x1B[36m"

void save_to_file(const char* filename, const uint8_t* data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("%s[FILE]%s Saved to %s\n", KGRN, KNRM, filename);
    }
}

void print_packet_info(int layer, const uint8_t* pkt) {
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    
    printf("%s--- Packet Info (Layer %d Context) ---%s\n", KYEL, layer, KNRM);
    if (layer >= 2) {
        printf("Eth Dest: %02x:%02x:%02x:%02x:%02x:%02x\n", 
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    }
    if (layer >= 3) {
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        printf("IP: %s -> %s (Proto: %d)\n", inet_ntoa(src), inet_ntoa(dst), ip->protocol);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <l2|l3|l4>\n", argv[0]);
        return 1;
    }

    int layer = 4;
    if (strcmp(argv[1], "l2") == 0) layer = 2;
    else if (strcmp(argv[1], "l3") == 0) layer = 3;
    else if (strcmp(argv[1], "l4") == 0) layer = 4;

    if (trf_pqc_init_global() != TRF_PQC_OK) return 1;

    uint8_t key[32] __attribute__((aligned(64)));
    uint8_t nonce[12] __attribute__((aligned(64)));
    trf_pqc_generate_random_key(key, 32);
    trf_pqc_generate_nonce(nonce);

    // 1. Tao goi tin mau (Eth + IP + TCP + Data)
    uint8_t packet[1024];
    memset(packet, 0, sizeof(packet));
    
    // Ethernet
    struct ethhdr *eth = (struct ethhdr *)packet;
    memset(eth->h_dest, 0xBB, 6);
    memset(eth->h_source, 0xAA, 6);
    eth->h_proto = htons(ETH_P_IP);

    // IP
    struct iphdr *ip = (struct iphdr *)(packet + 14);
    ip->version = 4; ip->ihl = 5; ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("1.1.1.1"); ip->daddr = inet_addr("2.2.2.2");
    ip->tot_len = htons(100);

    // TCP
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + 20);
    tcp->source = htons(1234); tcp->dest = htons(80);

    // Data
    strcpy((char*)(packet + 14 + 20 + 20), "PQC_TEST_DATA_CONTENT");

    size_t full_len = 14 + 20 + 20 + strlen("PQC_TEST_DATA_CONTENT") + 1;
    print_packet_info(layer, packet);

    // 2. Chuan bi AAD va Vung ma hoa theo tung Layer
    uint8_t aad[64] __attribute__((aligned(64)));
    int aad_len = 0;
    int enc_off = 0;

    if (layer == 4) {
        // AAD = IPs + Ports (12 bytes)
        memcpy(aad, &ip->saddr, 8);
        memcpy(aad + 8, &tcp->source, 4);
        aad_len = 12;
        enc_off = 14 + 20 + 20; // Ma hoa sau TCP Header
    } else if (layer == 3) {
        // AAD = IPs (8 bytes)
        memcpy(aad, &ip->saddr, 8);
        aad_len = 8;
        enc_off = 14 + 20; // Ma hoa sau IP Header (gồm cả TCP Header)
    } else {
        // AAD = MACs (12 bytes)
        memcpy(aad, eth->h_dest, 12);
        aad_len = 12;
        enc_off = 14; // Ma hoa sau Ethernet Header (gồm cả IP + TCP)
    }

    // 3. MA HOA
    int enc_payload_len = full_len - enc_off;
    int new_len;
    uint8_t encrypted_packet[1024];
    memcpy(encrypted_packet, packet, full_len);

    printf("%sEncrypting at Layer %d...%s\n", KBLU, layer, KNRM);
    if (trf_encrypt_payload_gcm(key, nonce, 12, aad, aad_len, 
                                encrypted_packet + enc_off, enc_payload_len, &new_len) == TRF_PQC_OK) {
        save_to_file("encrypt.bin", encrypted_packet, enc_off + new_len);
        
        // 4. GIAI MA
        int dec_len;
        if (trf_decrypt_payload_gcm(key, nonce, 12, aad, aad_len, 
                                    encrypted_packet + enc_off, new_len, &dec_len) == TRF_PQC_OK) {
            save_to_file("decrypt.bin", encrypted_packet, enc_off + dec_len);
            printf("%s[SUCCESS] Layer %d Crypto Cycle Complete.%s\n", KGRN, argv[1], KNRM);
        } else {
            printf("%s[FAIL] Decryption failed!%s\n", KRED, KNRM);
        }
    }

    trf_pqc_cleanup();
    return 0;
}
