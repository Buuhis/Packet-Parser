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
static bool g_key_ready = false;
static bool g_hs_started = false;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *g_global_id_priv = NULL;
static char *g_global_id_pub = NULL;
static char *g_peer_id_pub = NULL;

#define MAX_IDENTITY_REGISTRY 10

typedef struct {
    char fingerprint[16];
    char *priv_key;
    char *pub_key;
} identity_entry_t;

static identity_entry_t g_identity_registry[MAX_IDENTITY_REGISTRY];
static int g_registry_count = 0;

typedef struct {
    bool is_initiator;
    char peer_ip[64];
    char local_fingerprint[16];
} hs_config_t;

static hs_config_t g_hs_cfg;

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

// Helper to calculate HMAC-SHA256 for authentication
static void calculate_auth_tag(const char *key_str, const uint8_t *data, int len, uint8_t *out_tag) {
    if (!key_str || key_str[0] == '\0') {
        memset(out_tag, 0, PQC_AUTH_TAG_SZ);
        return;
    }
    trf_calculate_hmac(DIGEST_TYPE_SHA256, (const uint8_t *)key_str, (int)strlen(key_str), data, len, out_tag);
}

static void* pqc_handshake_thread(void* arg) {
    int sockfd;
    struct sockaddr_in servaddr, peeraddr;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[PQC-HS] Socket creation failed");
        return NULL;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PQC_HS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("[PQC-HS] Bind failed (Port 7090)");
        close(sockfd);
        return NULL;
    }

    memset(&peeraddr, 0, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(PQC_HS_PORT);
    
    printf("[PQC-HS] Handshake thread started. Role: %s\n", 
           g_hs_cfg.is_initiator ? "Initiator" : "Responder");
    fflush(stdout);

    while (!g_key_ready) {
        // 1. Wait for keys to be ready in RAM/DB
        pthread_mutex_lock(&g_key_mutex);
        char *my_priv = NULL;
        for (int i = 0; i < g_registry_count; i++) {
            if (strcmp(g_identity_registry[i].fingerprint, g_hs_cfg.local_fingerprint) == 0) {
                my_priv = g_identity_registry[i].priv_key;
                break;
            }
        }
        bool has_keys = (my_priv != NULL && g_peer_id_pub != NULL);
        char current_peer_ip[64];
        strncpy(current_peer_ip, g_hs_cfg.peer_ip, 63);
        pthread_mutex_unlock(&g_key_mutex);

        if (!has_keys) {
            sleep(2);
            continue;
        }

        inet_pton(AF_INET, current_peer_ip, &peeraddr.sin_addr);
        uint8_t pk[2048], sk[4096], ct[2048], ss[128];
        int pk_sz, sk_sz, ct_sz;

        if (g_hs_cfg.is_initiator) {
            // --- INITIATOR FLOW ---
            trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz);
            struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
            msg->magic = PQC_HS_MAGIC;
            msg->msg_type = PQC_HS_MSG_HELLO;
            msg->session_id = 123; 
            msg->data_len = (uint16_t)pk_sz;
            memcpy(msg->data, pk, pk_sz);
            
            pthread_mutex_lock(&g_key_mutex);
            calculate_auth_tag(my_priv, msg->data, pk_sz, msg->auth_tag);
            pthread_mutex_unlock(&g_key_mutex);

            while (!g_key_ready) {
                sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz, 0,
                       (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
                
                struct timeval tv = {2, 0};
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                socklen_t len = sizeof(peeraddr);
                int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
                if (n > 0) {
                    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                    if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                        uint8_t expected_tag[PQC_AUTH_TAG_SZ];
                        calculate_auth_tag(g_peer_id_pub, resp->data, resp->data_len, expected_tag);
                        
                        if (memcmp(resp->auth_tag, expected_tag, PQC_AUTH_TAG_SZ) == 0) {
                            if (trf_kem_decapsulate(sk, sk_sz, resp->data, resp->data_len, ss) == TRF_PQC_OK) {
                                pthread_mutex_lock(&g_key_mutex);
                                derive_traffic_key(ss, 32, g_traffic_key);
                                g_key_ready = true;
                                pthread_mutex_unlock(&g_key_mutex);
                                printf("[PQC-HS] Handshake SUCCESS!\n");
                                break;
                            }
                        }
                    }
                }
                printf("[PQC-HS] Initiator retrying HELLO...\n");
            }
        } else {
            // --- RESPONDER FLOW ---
            struct timeval tv = {1, 0};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            socklen_t len = sizeof(peeraddr);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
            if (n > 0) {
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                    uint8_t expected_tag[PQC_AUTH_TAG_SZ];
                    calculate_auth_tag(g_peer_id_pub, msg->data, msg->data_len, expected_tag);
                    
                    if (memcmp(msg->auth_tag, expected_tag, PQC_AUTH_TAG_SZ) == 0) {
                        if (trf_kem_encapsulate(msg->data, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                            resp->msg_type = PQC_HS_MSG_RESP;
                            resp->data_len = (uint16_t)ct_sz;
                            memcpy(resp->data, ct, ct_sz);
                            
                            pthread_mutex_lock(&g_key_mutex);
                            calculate_auth_tag(my_priv, resp->data, ct_sz, resp->auth_tag);
                            pthread_mutex_unlock(&g_key_mutex);

                            sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + ct_sz, 0,
                                   (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                            pthread_mutex_lock(&g_key_mutex);
                            derive_traffic_key(ss, 32, g_traffic_key);
                            g_key_ready = true;
                            pthread_mutex_unlock(&g_key_mutex);
                            printf("[PQC-HS] Responder Handshake SUCCESS!\n");
                        }
                    }
                }
            }
        }
    }

    close(sockfd);
    return NULL;
}

int sig_pqc_handshake_start(bool is_initiator, const char *peer_ip, 
                            const char *identity_priv, const char *identity_pub) {
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

void sig_pqc_add_to_registry(const char *fingerprint, const char *priv, const char *pub) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_registry_count >= MAX_IDENTITY_REGISTRY) {
        fprintf(stderr, "[PQC-REG] Registry full!\n");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }
    
    // Check if already exists
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            free(g_identity_registry[i].priv_key);
            free(g_identity_registry[i].pub_key);
            g_identity_registry[i].priv_key = strdup(priv);
            g_identity_registry[i].pub_key = strdup(pub);
            pthread_mutex_unlock(&g_key_mutex);
            return;
        }
    }

    identity_entry_t *entry = &g_identity_registry[g_registry_count++];
    strncpy(entry->fingerprint, fingerprint, 15);
    entry->priv_key = strdup(priv);
    entry->pub_key = strdup(pub);
    
    printf("[PQC-REG] Added identity fingerprint: %s to RAM Registry.\n", fingerprint);
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_set_handshake_config(bool is_initiator, const char *peer_ip, const char *local_fingerprint) {
    pthread_mutex_lock(&g_key_mutex);
    g_hs_cfg.is_initiator = is_initiator;
    strncpy(g_hs_cfg.peer_ip, peer_ip, 63);
    if (local_fingerprint) strncpy(g_hs_cfg.local_fingerprint, local_fingerprint, 15);
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_set_peer_identity(const char *pub) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_peer_id_pub) free(g_peer_id_pub);
    g_peer_id_pub = pub ? strdup(pub) : NULL;
    pthread_mutex_unlock(&g_key_mutex);
    if (pub) printf("[PQC-HS] Peer identity key loaded from DB. Ready for Handshake.\n");
}
