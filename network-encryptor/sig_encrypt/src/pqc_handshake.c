#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static uint8_t  g_traffic_key[PQC_TRAFFIC_KEY_SZ];
static bool     g_key_ready = false;
static bool     g_hs_started = false;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    bool is_initiator;
    char peer_ip[64];
} hs_config_t;

static hs_config_t g_hs_cfg;

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

static void* pqc_handshake_thread(void* arg) {
    (void)arg;
    int sockfd;
    struct sockaddr_in servaddr, peeraddr;
    uint8_t buffer[4096];
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[PQC-HS] Socket creation failed");
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PQC_HS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("[PQC-HS] Bind failed (Port 9999)");
        close(sockfd);
        return NULL;
    }

    memset(&peeraddr, 0, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(PQC_HS_PORT);
    inet_pton(AF_INET, g_hs_cfg.peer_ip, &peeraddr.sin_addr);

    printf("[PQC-HS] Handshake thread started. Peer: %s, Role: %s\n", 
           g_hs_cfg.peer_ip, g_hs_cfg.is_initiator ? "Initiator" : "Responder");
    fflush(stdout);

    uint8_t pk[2048], sk[4096], ct[2048], ss[128];
    int pk_sz, sk_sz, ct_sz;

    if (g_hs_cfg.is_initiator) {
        trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz);
        struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
        msg->magic = PQC_HS_MAGIC;
        msg->msg_type = PQC_HS_MSG_HELLO;
        msg->session_id = rand();
        msg->data_len = (uint16_t)pk_sz;
        memcpy(msg->data, pk, pk_sz);

        while (!g_key_ready) {
            sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz, 0,
                   (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
            
            struct timeval tv;
            tv.tv_sec = 2; tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            socklen_t len = sizeof(peeraddr);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
            if (n > 0) {
                struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                    if (trf_kem_decapsulate(sk, sk_sz, resp->data, resp->data_len, ss) == TRF_PQC_OK) {
                        pthread_mutex_lock(&g_key_mutex);
                        derive_traffic_key(ss, 32, g_traffic_key);
                        g_key_ready = true;
                        printf("[PQC-HS] Handshake SUCCESS! Final Traffic Key: ");
                        for(int i=0; i<PQC_TRAFFIC_KEY_SZ; i++) printf("%02x", g_traffic_key[i]);
                        printf("\n");
                        fflush(stdout);
                        pthread_mutex_unlock(&g_key_mutex);
                        break;
                    }
                }
            } else {
                printf("[PQC-HS] HELLO timeout, retrying...\n");
                fflush(stdout);
            }
        }
    } else {
        printf("[PQC-HS] Waiting for HELLO from initiator...\n");
        fflush(stdout);
        while (!g_key_ready) {
            socklen_t len = sizeof(peeraddr);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
            if (n > 0) {
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                    printf("[PQC-HS] Received HELLO. Encapsulating...\n");
                    if (trf_kem_encapsulate(msg->data, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                        struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                        resp->magic = PQC_HS_MAGIC;
                        resp->msg_type = PQC_HS_MSG_RESP;
                        resp->data_len = (uint16_t)ct_sz;
                        memcpy(resp->data, ct, ct_sz);
                        sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + ct_sz, 0,
                               (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                        pthread_mutex_lock(&g_key_mutex);
                        derive_traffic_key(ss, 32, g_traffic_key);
                        g_key_ready = true;
                        printf("[PQC-HS] Handshake SUCCESS! Final Traffic Key: ");
                        for(int i=0; i<PQC_TRAFFIC_KEY_SZ; i++) printf("%02x", g_traffic_key[i]);
                        printf("\n");
                        fflush(stdout);
                        pthread_mutex_unlock(&g_key_mutex);
                        break;
                    }
                }
            }
        }
    }
    close(sockfd);
    return NULL;
}

int sig_pqc_handshake_start(bool is_initiator, const char *peer_ip) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_hs_started) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }
    g_hs_started = true;
    pthread_mutex_unlock(&g_key_mutex);

    g_hs_cfg.is_initiator = is_initiator;
    strncpy(g_hs_cfg.peer_ip, peer_ip, 63);
    
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, pqc_handshake_thread, NULL) != 0) {
        pthread_mutex_lock(&g_key_mutex);
        g_hs_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    pthread_detach(thread_id);
    return 0;
}

bool sig_pqc_is_key_ready(void) {
    pthread_mutex_lock(&g_key_mutex);
    bool ready = g_key_ready;
    pthread_mutex_unlock(&g_key_mutex);
    return ready;
}

int sig_pqc_get_traffic_key(uint8_t out_key[PQC_TRAFFIC_KEY_SZ]) {
    pthread_mutex_lock(&g_key_mutex);
    if (!g_key_ready) {
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    memcpy(out_key, g_traffic_key, PQC_TRAFFIC_KEY_SZ);
    pthread_mutex_unlock(&g_key_mutex);
    return 0;
}
