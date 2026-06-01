#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include "../inc/traffic_crypto.h"
#include "../inc/crypt.h"

#define TEST_ITERATIONS 100000
#define TAG_SIZE_GCM 16

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void run_scenario_a(SCryptCipherCtx* ctx, const uint8_t* key, uint8_t* data, int payload_len) {
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t tag[TAG_SIZE_GCM];
    word32 tagLen = TAG_SIZE_GCM;
    word32 outLen = 0, finalLen = 0;

    uint64_t start = get_time_ns();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        // Increment nonce to simulate real-world packet unique nonces
        nonce[0] = (uint8_t)(i & 0xFF);
        nonce[1] = (uint8_t)((i >> 8) & 0xFF);

        // Scenario A: Full initialization on every packet
        scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, 12, SCRYPT_ENCRYPTION);
        scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);
        
        scrypt_CipherUpdate(ctx, data, payload_len, data, &outLen);
        scrypt_CipherFinal(ctx, data + outLen, &finalLen);
        scrypt_CipherGetTag(ctx, tag, &tagLen);
    }
    uint64_t duration = get_time_ns() - start;
    double sec = (double)duration / 1000000000.0;
    double pps = (double)TEST_ITERATIONS / sec;
    double mbps = (pps * (double)payload_len * 8.0) / 1000000.0;
    double latency = (double)duration / (double)TEST_ITERATIONS;

    printf("  [Scenario A - Full Init Per Packet]\n");
    printf("    Payload size : %d bytes\n", payload_len);
    printf("    Total time   : %.4f seconds\n", sec);
    printf("    Throughput   : %.2f Mbps\n", mbps);
    printf("    Packet Rate  : %.2f pps\n", pps);
    printf("    Latency      : %.1f ns/packet\n\n", latency);
}

void run_scenario_b(SCryptCipherCtx* ctx, const uint8_t* key, uint8_t* data, int payload_len) {
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t tag[TAG_SIZE_GCM];
    word32 tagLen = TAG_SIZE_GCM;
    word32 outLen = 0, finalLen = 0;

    // Test first if key = NULL is supported by the library
    nonce[0] = 0xFF;
    int test_ret = scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, NULL, 0, nonce, 12, SCRYPT_ENCRYPTION);
    int supported = (test_ret == 0);

    if (!supported) {
        printf("  [Scenario B - Key=NULL Reuse IV/Nonce]\n");
        printf("    --> STATUS: NOT SUPPORTED by the libscrypt library (returned %d)\n\n", test_ret);
        return;
    }

    uint64_t start = get_time_ns();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        nonce[0] = (uint8_t)(i & 0xFF);
        nonce[1] = (uint8_t)((i >> 8) & 0xFF);

        // Scenario B: Reuse Key Schedule, only reset Nonce/IV
        scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, NULL, 0, nonce, 12, SCRYPT_ENCRYPTION);
        scrypt_CipherSetTagSize(ctx, TAG_SIZE_GCM);
        
        scrypt_CipherUpdate(ctx, data, payload_len, data, &outLen);
        scrypt_CipherFinal(ctx, data + outLen, &finalLen);
        scrypt_CipherGetTag(ctx, tag, &tagLen);
    }
    uint64_t duration = get_time_ns() - start;
    double sec = (double)duration / 1000000000.0;
    double pps = (double)TEST_ITERATIONS / sec;
    double mbps = (pps * (double)payload_len * 8.0) / 1000000.0;
    double latency = (double)duration / (double)TEST_ITERATIONS;

    printf("  [Scenario B - Key=NULL Reuse IV/Nonce]\n");
    printf("    Payload size : %d bytes\n", payload_len);
    printf("    Total time   : %.4f seconds\n", sec);
    printf("    Throughput   : %.2f Mbps\n", mbps);
    printf("    Packet Rate  : %.2f pps\n", pps);
    printf("    Latency      : %.1f ns/packet\n\n", latency);
}

int main(void) {
    printf("===================================================\n");
    printf("   PQC AES-GCM CRYPTOGRAPHIC BENCHMARK TOOL\n");
    printf("===================================================\n\n");

    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "Failed to initialize PQC global context\n");
        return 1;
    }

    SCryptCipherCtx* ctx = scrypt_CipherCtxNew();
    if (!ctx) {
        fprintf(stderr, "Failed to create Cipher context\n");
        return 1;
    }

    uint8_t key[32];
    memset(key, 0x42, 32);

    uint8_t* payload = malloc(2048);
    memset(payload, 0xAA, 2048);

    // Run tests for different packet sizes
    int sizes[] = {64, 512, 1400};
    for (int s = 0; s < 3; s++) {
        int sz = sizes[s];
        printf("--- Running Benchmark for Packet Size: %d bytes ---\n", sz);
        run_scenario_a(ctx, key, payload, sz);
        run_scenario_b(ctx, key, payload, sz);
    }

    free(payload);
    scrypt_CipherCtxFree(ctx);
    trf_pqc_cleanup();

    printf("===================================================\n");
    printf("   Benchmark Complete\n");
    printf("===================================================\n");
    return 0;
}
