#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include "../inc/pqc_l2_handshake.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

// Declare as weak so that test programs (like db-loader-test) that do not link forwarder.c will compile successfully.
__attribute__((weak)) void forwarder_pre_diversify_pqc_keys(int profile_id) {
    (void)profile_id;
}

static uint8_t  g_traffic_key[PQC_TRAFFIC_KEY_SZ];
static bool g_key_ready = false;
static bool g_hs_started = false;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *g_peer_id_pub = NULL;

// --- RX Packet Feed Queue (fed by forwarder, consumed by handshake thread) ---
#define PQC_RX_QUEUE_SIZE  16
#define PQC_RX_PKT_MAX     10000

typedef struct {
    uint8_t data[PQC_RX_PKT_MAX];
    int     len;
} pqc_rx_slot_t;

static pqc_rx_slot_t   g_rx_queue[PQC_RX_QUEUE_SIZE];
static int              g_rx_head = 0;  // write index (producer)
static int              g_rx_tail = 0;  // read index (consumer)
static pthread_mutex_t  g_rx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_rx_cond  = PTHREAD_COND_INITIALIZER;

void sig_pqc_feed_rx_packet(const uint8_t *udp_payload, int payload_len) {
    if (payload_len <= 0 || payload_len > PQC_RX_PKT_MAX) return;
    pthread_mutex_lock(&g_rx_mutex);
    int next = (g_rx_head + 1) % PQC_RX_QUEUE_SIZE;
    if (next != g_rx_tail) {  // drop if queue full
        memcpy(g_rx_queue[g_rx_head].data, udp_payload, payload_len);
        g_rx_queue[g_rx_head].len = payload_len;
        g_rx_head = next;
        pthread_cond_signal(&g_rx_cond);
    }
    pthread_mutex_unlock(&g_rx_mutex);
}

// Blocking receive from the feed queue (with timeout in milliseconds)
static int pqc_rx_recv(uint8_t *buf, int buf_sz, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&g_rx_mutex);
    while (g_rx_head == g_rx_tail) {
        if (pthread_cond_timedwait(&g_rx_cond, &g_rx_mutex, &ts) != 0) {
            pthread_mutex_unlock(&g_rx_mutex);
            return -1;  // timeout
        }
    }
    int len = g_rx_queue[g_rx_tail].len;
    if (len > buf_sz) len = buf_sz;
    memcpy(buf, g_rx_queue[g_rx_tail].data, len);
    g_rx_tail = (g_rx_tail + 1) % PQC_RX_QUEUE_SIZE;
    pthread_mutex_unlock(&g_rx_mutex);
    return len;
}

#define MAX_IDENTITY_REGISTRY 10

typedef struct {
    char fingerprint[16];
    char *priv_key;
    char *pub_key;
} identity_entry_t;

static identity_entry_t g_identity_registry[MAX_IDENTITY_REGISTRY];
static int g_registry_count = 0;

typedef struct {
    int profile_id;
    char *local_priv;
    char *local_pub;
    char *peer_pub;
    uint8_t master_traffic_key[PQC_TRAFFIC_KEY_SZ];
    bool key_ready;
} profile_key_binding_t;

static profile_key_binding_t g_profile_bindings[MAX_IDENTITY_REGISTRY];
static int g_profile_bindings_count = 0;

typedef struct {
    int profile_id;
    bool is_initiator;
    char peer_ip[64];
    char local_fingerprint[16];
    char wan_ifname[64];
} hs_config_t;

static hs_config_t g_hs_cfg;

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

// (HMAC helper removed as we now use actual ML-DSA signatures)

static int get_interface_mac(const char *ifname, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static uint64_t get_time_ms_hs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void* pqc_l2_handshake_thread_run(void) {
    fprintf(stderr, "[PQC-HS-L2] Pure L2 Bridge Mode Handshake Thread started on interface %s\n", g_hs_cfg.wan_ifname);

    char *my_priv = NULL;
    char *my_pub = NULL;

    // 1. Wait for keys to be loaded in RAM/DB
    while (1) {
        pthread_mutex_lock(&g_key_mutex);
        for (int i = 0; i < g_registry_count; i++) {
            if (strcmp(g_identity_registry[i].fingerprint, g_hs_cfg.local_fingerprint) == 0) {
                my_priv = g_identity_registry[i].priv_key;
                my_pub = g_identity_registry[i].pub_key;
                break;
            }
        }
        bool has_keys = (my_priv != NULL && my_pub != NULL && g_peer_id_pub != NULL);
        pthread_mutex_unlock(&g_key_mutex);

        if (has_keys) break;
        usleep(200000);
    }

    // 2. Initialize L2 Peer
    struct pqc_l2_peer peer;
    if (pqc_l2_init_peer(&peer, g_hs_cfg.wan_ifname) < 0) {
        fprintf(stderr, "[PQC-HS-L2] Failed to initialize L2 peer on interface %s\n", g_hs_cfg.wan_ifname);
        return NULL;
    }

    uint8_t pk[2048], sk[4096], ct[2048], ss[128];
    int pk_sz, sk_sz, ct_sz;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    if (g_hs_cfg.is_initiator) {
        // --- INITIATOR FLOW ---
        // A. Discover peer MAC
        fprintf(stderr, "[PQC-HS-L2] Initiating peer MAC discovery...\n");
        while (!g_key_ready) {
            if (pqc_l2_discover_peer_mac(&peer, 5) == 0) {
                break;
            }
            usleep(1000000);
        }

        // B. Generate keys
        trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz);
        struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
        msg->magic = PQC_HS_MAGIC;
        msg->msg_type = PQC_HS_MSG_HELLO;
        msg->session_id = 123; 
        msg->data_len = (uint16_t)pk_sz;
        memcpy(msg->payload, pk, pk_sz);
        
        pthread_mutex_lock(&g_key_mutex);
        size_t raw_priv_sz = 0;
        uint8_t raw_priv[8192];
        trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
        int sig_sz = 0;
        trf_dsa_sign_payload(raw_priv, raw_priv_sz, msg->payload, pk_sz, msg->payload + pk_sz, &sig_sz);
        msg->sig_len = (uint16_t)sig_sz;
        pthread_mutex_unlock(&g_key_mutex);

        uint32_t payload_tot_sz = sizeof(struct pqc_hs_msg) + pk_sz + sig_sz;
        uint32_t msg_id = 12345;
        int retry_cnt = 0;

        while (!g_key_ready && retry_cnt < 10) {
            fprintf(stderr, "[PQC-HS-L2] Initiator sending HELLO fragments (msg_id: %u, try: %d)...\n", msg_id, retry_cnt + 1);
            pqc_l2_send_payload_fragmented(&peer, msg_id, buffer, payload_tot_sz);

            uint64_t start_rx = get_time_ms_hs();
            while (get_time_ms_hs() - start_rx < 3000 && !g_key_ready) {
                uint8_t *rx_payload = NULL;
                uint32_t rx_msg_id = 0;
                int rx_len = pqc_l2_recv_and_process(&peer, &rx_payload, &rx_msg_id);
                if (rx_len > 0) {
                    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)rx_payload;
                    if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                        pthread_mutex_lock(&g_key_mutex);
                        size_t raw_pub_sz = 0;
                        uint8_t raw_pub[8192];
                        trf_base64_decode(g_peer_id_pub, raw_pub, &raw_pub_sz);
                        pthread_mutex_unlock(&g_key_mutex);

                        if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, resp->payload, resp->data_len, resp->payload + resp->data_len, resp->sig_len) == TRF_PQC_OK) {
                            if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                                uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                derive_traffic_key(ss, 32, derived_master);

                                pthread_mutex_lock(&g_key_mutex);
                                memcpy(g_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                g_key_ready = true;
                                for (int b_idx = 0; b_idx < g_profile_bindings_count; b_idx++) {
                                    if (g_profile_bindings[b_idx].profile_id == g_hs_cfg.profile_id) {
                                        memcpy(g_profile_bindings[b_idx].master_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                        g_profile_bindings[b_idx].key_ready = true;
                                        break;
                                    }
                                }
                                pthread_mutex_unlock(&g_key_mutex);
                                fprintf(stderr, "[PQC-HS-L2] Handshake SUCCESS!\n");
                                forwarder_pre_diversify_pqc_keys(g_hs_cfg.profile_id);
                                free(rx_payload);
                                break;
                            }
                        }
                    }
                    free(rx_payload);
                }
                usleep(10000);
            }
            retry_cnt++;
        }
    } else {
        // --- RESPONDER FLOW ---
        fprintf(stderr, "[PQC-HS-L2] Responder listening for HELLO fragments...\n");
        while (!g_key_ready) {
            uint8_t *rx_payload = NULL;
            uint32_t rx_msg_id = 0;
            int rx_len = pqc_l2_recv_and_process(&peer, &rx_payload, &rx_msg_id);
            if (rx_len > 0) {
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)rx_payload;
                if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                    pthread_mutex_lock(&g_key_mutex);
                    size_t raw_pub_sz = 0;
                    uint8_t raw_pub[8192];
                    trf_base64_decode(g_peer_id_pub, raw_pub, &raw_pub_sz);
                    pthread_mutex_unlock(&g_key_mutex);

                    if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                        fprintf(stderr, "[PQC-HS-L2] Responder HELLO signature verified! Encapsulating...\n");
                        if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                            resp->magic = PQC_HS_MAGIC;
                            resp->msg_type = PQC_HS_MSG_RESP;
                            resp->session_id = msg->session_id;
                            resp->data_len = (uint16_t)ct_sz;
                            memcpy(resp->payload, ct, ct_sz);

                            pthread_mutex_lock(&g_key_mutex);
                            size_t raw_priv_sz = 0;
                            uint8_t raw_priv[8192];
                            trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
                            int sig_sz = 0;
                            trf_dsa_sign_payload(raw_priv, raw_priv_sz, resp->payload, ct_sz, resp->payload + ct_sz, &sig_sz);
                            resp->sig_len = (uint16_t)sig_sz;
                            pthread_mutex_unlock(&g_key_mutex);

                            // Reply back over segmented L2 frames
                            fprintf(stderr, "[PQC-HS-L2] Responder sending RESP fragments (msg_id: %u)...\n", rx_msg_id);
                            pqc_l2_send_payload_fragmented(&peer, rx_msg_id, buffer, sizeof(struct pqc_hs_msg) + ct_sz + sig_sz);

                            uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                            derive_traffic_key(ss, 32, derived_master);

                            pthread_mutex_lock(&g_key_mutex);
                            memcpy(g_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                            g_key_ready = true;
                            for (int b_idx = 0; b_idx < g_profile_bindings_count; b_idx++) {
                                if (g_profile_bindings[b_idx].profile_id == g_hs_cfg.profile_id) {
                                    memcpy(g_profile_bindings[b_idx].master_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                    g_profile_bindings[b_idx].key_ready = true;
                                    break;
                                }
                            }
                            pthread_mutex_unlock(&g_key_mutex);
                            fprintf(stderr, "[PQC-HS-L2] Responder Handshake SUCCESS!\n");
                            forwarder_pre_diversify_pqc_keys(g_hs_cfg.profile_id);
                        }
                    }
                }
                free(rx_payload);
            }
            usleep(10000);
        }
    }

    pqc_l2_cleanup_peer(&peer);
    return NULL;
}

static void* pqc_handshake_thread(void* arg) {
    pthread_mutex_lock(&g_key_mutex);
    char current_peer_ip[64];
    strncpy(current_peer_ip, g_hs_cfg.peer_ip, 63);
    char wan_ifname[64];
    strncpy(wan_ifname, g_hs_cfg.wan_ifname, 63);
    pthread_mutex_unlock(&g_key_mutex);

    bool is_bridge_mode = (strlen(wan_ifname) > 0 && 
                          (strlen(current_peer_ip) == 0 || strcmp(current_peer_ip, "0.0.0.0") == 0));

    if (is_bridge_mode) {
        return pqc_l2_handshake_thread_run();
    }

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

    inet_pton(AF_INET, current_peer_ip, &peeraddr.sin_addr);

    // ----- STAGE 1: DB-DRIVEN ROLE CONFIGURATION -----
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    fprintf(stderr, "[PQC-HS] ROLE SETTLED FROM DB CONFIG: Role: %s, Peer IP: %s\n",
            g_hs_cfg.is_initiator ? "INITIATOR" : "RESPONDER", current_peer_ip);
    fflush(stdout);

    // ----- STAGE 2: MAIN ML-KEM/ML-DSA HANDSHAKE -----
    while (!g_key_ready) {
        // 1. Wait for keys to be ready in RAM/DB
        pthread_mutex_lock(&g_key_mutex);
        char *my_priv = NULL;
        char *my_pub = NULL;
        for (int i = 0; i < g_registry_count; i++) {
            if (strcmp(g_identity_registry[i].fingerprint, g_hs_cfg.local_fingerprint) == 0) {
                my_priv = g_identity_registry[i].priv_key;
                my_pub = g_identity_registry[i].pub_key;
                break;
            }
        }
        bool has_keys = (my_priv != NULL && my_pub != NULL && g_peer_id_pub != NULL);
        char current_peer_ip[64];
        strncpy(current_peer_ip, g_hs_cfg.peer_ip, 63);
        pthread_mutex_unlock(&g_key_mutex);

        if (!has_keys) {
            // Simple sleep to wait for keys to load
            usleep(200000);
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
            memcpy(msg->payload, pk, pk_sz);
            
            pthread_mutex_lock(&g_key_mutex);
            size_t raw_priv_sz = 0;
            uint8_t raw_priv[8192];
            trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
            
            int sig_sz = 0;
            trf_dsa_sign_payload(raw_priv, raw_priv_sz, msg->payload, pk_sz, msg->payload + pk_sz, &sig_sz);
            msg->sig_len = (uint16_t)sig_sz;
            pthread_mutex_unlock(&g_key_mutex);

            while (!g_key_ready) {
                sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz + sig_sz, 0,
                       (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
                
                int n = pqc_rx_recv(buffer, sizeof(buffer), 200);
                if (n <= 0) {
                    struct sockaddr_in from_addr;
                    socklen_t from_len = sizeof(from_addr);
                    n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&from_addr, &from_len);
                }
                if (n > 0) {
                    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                    if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                        int expected_sz = sizeof(struct pqc_hs_msg) + resp->data_len + resp->sig_len;
                        fprintf(stderr, "[PQC-HS] Initiator received RESP. Total bytes rcvd (n) = %d, expected = %d\n", n, expected_sz);
                        pthread_mutex_lock(&g_key_mutex);
                        size_t raw_pub_sz = 0;
                        uint8_t raw_pub[8192];
                        trf_base64_decode(g_peer_id_pub, raw_pub, &raw_pub_sz);
                        pthread_mutex_unlock(&g_key_mutex);

                        if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, resp->payload, resp->data_len, resp->payload + resp->data_len, resp->sig_len) == TRF_PQC_OK) {
                            if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                                uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                derive_traffic_key(ss, 32, derived_master);

                                pthread_mutex_lock(&g_key_mutex);
                                memcpy(g_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                g_key_ready = true;

                                for (int b_idx = 0; b_idx < g_profile_bindings_count; b_idx++) {
                                    if (g_profile_bindings[b_idx].profile_id == g_hs_cfg.profile_id) {
                                        memcpy(g_profile_bindings[b_idx].master_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                        fprintf(stderr, "[PQC-HS-DEBUG] BEFORE write: b_idx=%d, key_ready=%d\n", b_idx, (int)g_profile_bindings[b_idx].key_ready);
                                         
                                        g_profile_bindings[b_idx].key_ready = true;
                                        fprintf(stderr, "[PQC-HS-DEBUG] AFTER standard write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                         
                                        g_profile_bindings[b_idx].key_ready = 1;
                                        fprintf(stderr, "[PQC-HS-DEBUG] AFTER integer 1 write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                         
                                        volatile bool *v_ptr = &g_profile_bindings[b_idx].key_ready;
                                        *v_ptr = true;
                                        fprintf(stderr, "[PQC-HS-DEBUG] AFTER volatile write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                         
                                        fprintf(stderr, "[PQC-HS-DEBUG] b_idx=%d, key_ready address=%p, size=%zu, raw_value=%d\n",
                                                b_idx, (void*)&g_profile_bindings[b_idx].key_ready, sizeof(g_profile_bindings[b_idx].key_ready),
                                                (int)g_profile_bindings[b_idx].key_ready);
                                        fprintf(stderr, "[PQC-HS-DEBUG] SET READY (Initiator): profile_id=%d, b_idx=%d, array_addr=%p\n",
                                                g_hs_cfg.profile_id, b_idx, (void*)g_profile_bindings);
                                        for (int i = 0; i < g_profile_bindings_count; i++) {
                                            fprintf(stderr, "[PQC-HS-DEBUG]   -> Binding[%d]: profile_id=%d, key_ready=%d\n",
                                                    i, g_profile_bindings[i].profile_id,
                                                    (int)g_profile_bindings[i].key_ready);
                                        }
                                        fprintf(stderr, "[PQC-HS] Master key bound to profile %d successfully!\n", g_hs_cfg.profile_id);
                                        fprintf(stderr, "[PQC-HS]   -> Master Key (first 8 bytes): %02X%02X%02X%02X%02X%02X%02X%02X\n",
                                                derived_master[0], derived_master[1], derived_master[2], derived_master[3],
                                                derived_master[4], derived_master[5], derived_master[6], derived_master[7]);
                                        break;
                                    }
                                }
                                pthread_mutex_unlock(&g_key_mutex);
                                fprintf(stderr, "[PQC-HS] Handshake SUCCESS!\n");
                                forwarder_pre_diversify_pqc_keys(g_hs_cfg.profile_id);
                                break;
                            }
                        }
                    }
                }
                fprintf(stderr, "[PQC-HS] Initiator retrying HELLO...\n");
            }
        } else {
            // --- RESPONDER FLOW ---
            int n = pqc_rx_recv(buffer, sizeof(buffer), 200);
            if (n <= 0) {
                struct sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);
                n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&from_addr, &from_len);
            }
            if (n > 0) {
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                    int expected_sz = sizeof(struct pqc_hs_msg) + msg->data_len + msg->sig_len;
                    fprintf(stderr, "[PQC-HS] Responder received HELLO. Total bytes rcvd (n) = %d, expected = %d\n", n, expected_sz);
                    pthread_mutex_lock(&g_key_mutex);
                    size_t raw_pub_sz = 0;
                    uint8_t raw_pub[8192];
                    trf_base64_decode(g_peer_id_pub, raw_pub, &raw_pub_sz);
                    pthread_mutex_unlock(&g_key_mutex);

                    if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                        fprintf(stderr, "[PQC-HS] Responder HELLO signature verified! Encapsulating...\n");
                        if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                            fprintf(stderr, "[PQC-HS] Responder KEM encapsulation successful.\n");
                            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                            resp->msg_type = PQC_HS_MSG_RESP;
                            resp->data_len = (uint16_t)ct_sz;
                            memcpy(resp->payload, ct, ct_sz);
                            
                            pthread_mutex_lock(&g_key_mutex);
                            size_t raw_priv_sz = 0;
                            uint8_t raw_priv[8192];
                            trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
                            
                            int sig_sz = 0;
                            trf_dsa_sign_payload(raw_priv, raw_priv_sz, resp->payload, ct_sz, resp->payload + ct_sz, &sig_sz);
                            resp->sig_len = (uint16_t)sig_sz;
                            pthread_mutex_unlock(&g_key_mutex);

                            sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + ct_sz + sig_sz, 0,
                                   (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                            uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                            derive_traffic_key(ss, 32, derived_master);

                            pthread_mutex_lock(&g_key_mutex);
                            memcpy(g_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                            g_key_ready = true;

                            for (int b_idx = 0; b_idx < g_profile_bindings_count; b_idx++) {
                                if (g_profile_bindings[b_idx].profile_id == g_hs_cfg.profile_id) {
                                    memcpy(g_profile_bindings[b_idx].master_traffic_key, derived_master, PQC_TRAFFIC_KEY_SZ);
                                    fprintf(stderr, "[PQC-HS-DEBUG] BEFORE write: b_idx=%d, key_ready=%d\n", b_idx, (int)g_profile_bindings[b_idx].key_ready);
                                    
                                    g_profile_bindings[b_idx].key_ready = true;
                                    fprintf(stderr, "[PQC-HS-DEBUG] AFTER standard write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                    
                                    g_profile_bindings[b_idx].key_ready = 1;
                                    fprintf(stderr, "[PQC-HS-DEBUG] AFTER integer 1 write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                    
                                    volatile bool *v_ptr = &g_profile_bindings[b_idx].key_ready;
                                    *v_ptr = true;
                                    fprintf(stderr, "[PQC-HS-DEBUG] AFTER volatile write: key_ready=%d\n", (int)g_profile_bindings[b_idx].key_ready);
                                    
                                    fprintf(stderr, "[PQC-HS-DEBUG] b_idx=%d, key_ready address=%p, size=%zu, raw_value=%d\n",
                                            b_idx, (void*)&g_profile_bindings[b_idx].key_ready, sizeof(g_profile_bindings[b_idx].key_ready),
                                            (int)g_profile_bindings[b_idx].key_ready);
                                    fprintf(stderr, "[PQC-HS-DEBUG] SET READY (Responder): profile_id=%d, b_idx=%d, array_addr=%p\n",
                                            g_hs_cfg.profile_id, b_idx, (void*)g_profile_bindings);
                                    for (int i = 0; i < g_profile_bindings_count; i++) {
                                        fprintf(stderr, "[PQC-HS-DEBUG]   -> Binding[%d]: profile_id=%d, key_ready=%d\n",
                                                i, g_profile_bindings[i].profile_id,
                                                (int)g_profile_bindings[i].key_ready);
                                    }
                                    fprintf(stderr, "[PQC-HS] Master key bound to profile %d successfully!\n", g_hs_cfg.profile_id);
                                    fprintf(stderr, "[PQC-HS]   -> Master Key (first 8 bytes): %02X%02X%02X%02X%02X%02X%02X%02X\n",
                                            derived_master[0], derived_master[1], derived_master[2], derived_master[3],
                                            derived_master[4], derived_master[5], derived_master[6], derived_master[7]);
                                    break;
                                }
                            }
                            pthread_mutex_unlock(&g_key_mutex);
                            fprintf(stderr, "[PQC-HS] Responder Handshake SUCCESS!\n");
                            forwarder_pre_diversify_pqc_keys(g_hs_cfg.profile_id);
                        } else {
                            fprintf(stderr, "[PQC-HS] ERROR: Responder KEM encapsulation failed!\n");
                        }
                    } else {
                        fprintf(stderr, "[PQC-HS] ERROR: Responder signature verification FAILED!\n");
                    }
                } else {
                    fprintf(stderr, "[PQC-HS] Responder received unknown packet (len=%d, magic=0x%X)\n", n, msg->magic);
                }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "[PQC-HS] Responder recvfrom error: %s\n", strerror(errno));
            }
        }
    }

    close(sockfd);
    return NULL;
}

int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_hs_started) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }
    g_hs_started = true;
    g_hs_cfg.profile_id = profile_id;
    pthread_mutex_unlock(&g_key_mutex);

    if (wan_ifname) strncpy(g_hs_cfg.wan_ifname, wan_ifname, 63);
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

int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key) {
    pthread_mutex_lock(&g_key_mutex);
    
    printf("[PQC-DEBUG] sig_pqc_diversify_key (policy_id=%d, profile_id=%d): g_profile_bindings_count = %d, array_addr = %p\n",
           policy_id, profile_id, g_profile_bindings_count, (void*)g_profile_bindings);
    for (int i = 0; i < g_profile_bindings_count; i++) {
        printf("[PQC-DEBUG]   -> Binding[%d]: profile_id=%d, key_ready=%s, master_traffic_key_addr=%p\n",
               i, g_profile_bindings[i].profile_id,
               g_profile_bindings[i].key_ready ? "TRUE" : "FALSE",
               (void*)g_profile_bindings[i].master_traffic_key);
    }

    profile_key_binding_t *binding = NULL;
    for (int i = 0; i < g_profile_bindings_count; i++) {
        if (g_profile_bindings[i].profile_id == profile_id) {
            binding = &g_profile_bindings[i];
            break;
        }
    }
    
    if (!binding) {
        printf("[PQC-DEBUG] sig_pqc_diversify_key: NO binding found for profile_id %d!\n", profile_id);
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    if (!binding->key_ready) {
        printf("[PQC-DEBUG] sig_pqc_diversify_key: Binding found for profile_id %d, but key_ready is FALSE!\n",
               profile_id);
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    
    // Diversify key: Policy_Key = HMAC-SHA256(Master_Key, policy_id)
    uint8_t mac_out[32];
    uint8_t msg[4];
    msg[0] = (policy_id >> 24) & 0xFF;
    msg[1] = (policy_id >> 16) & 0xFF;
    msg[2] = (policy_id >> 8) & 0xFF;
    msg[3] = policy_id & 0xFF;
    
    int ret = trf_calculate_hmac(DIGEST_TYPE_SHA256, binding->master_traffic_key, PQC_TRAFFIC_KEY_SZ,
                                 msg, 4, mac_out);
    if (ret == TRF_PQC_OK) {
        memcpy(out_policy_key, mac_out, PQC_TRAFFIC_KEY_SZ);
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }
    
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
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
    
    fprintf(stderr, "[PQC-REG] Added identity fingerprint: %s to RAM Registry.\n", fingerprint);
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_set_handshake_config(int profile_id, bool is_initiator, const char *peer_ip, const char *local_fingerprint, const char *wan_ifname) {
    pthread_mutex_lock(&g_key_mutex);
    g_hs_cfg.profile_id = profile_id;
    g_hs_cfg.is_initiator = is_initiator;
    strncpy(g_hs_cfg.peer_ip, peer_ip, 63);
    if (local_fingerprint) strncpy(g_hs_cfg.local_fingerprint, local_fingerprint, 15);
    if (wan_ifname) strncpy(g_hs_cfg.wan_ifname, wan_ifname, 63);
    pthread_mutex_unlock(&g_key_mutex);
}

static char* deobfuscate_peer_pub(const char *obf_pub_str, const char *peer_fingerprint) {
    if (!obf_pub_str || strlen(obf_pub_str) == 0) return NULL;

    // Clean up input string (trim whitespace/newlines)
    char clean_obf[8192];
    strncpy(clean_obf, obf_pub_str, sizeof(clean_obf) - 1);
    clean_obf[sizeof(clean_obf) - 1] = '\0';
    
    size_t len = strlen(clean_obf);
    while (len > 0 && (clean_obf[len - 1] == '\r' || clean_obf[len - 1] == '\n' || clean_obf[len - 1] == ' ')) {
        clean_obf[len - 1] = '\0';
        len--;
    }

    // Method 0: If fingerprint is provided in DB, de-obfuscate directly!
    if (peer_fingerprint && strlen(peer_fingerprint) > 0) {
        unsigned char raw_pub[4096];
        size_t raw_pub_len = 0;
        trf_base64_decode_obfuscated(clean_obf, peer_fingerprint, raw_pub, &raw_pub_len);

        char *plain_b64_pub = malloc(8192);
        memset(plain_b64_pub, 0, 8192);
        trf_base64_encode(raw_pub, raw_pub_len, plain_b64_pub);
        
        fprintf(stderr, "[PQC-HS] De-obfuscated peer pub key using DB fingerprint [%s].\n", peer_fingerprint);
        return plain_b64_pub;
    }

    // Method 1: Scan /etc/.enc_config/ for matching public key file to get fingerprint (Fallback)
    DIR *dir = opendir("/etc/.enc_config");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "identity_", 9) == 0 && strstr(entry->d_name, "_pub.key") != NULL) {
                char fingerprint[16];
                memset(fingerprint, 0, sizeof(fingerprint));
                strncpy(fingerprint, entry->d_name + 9, 8);

                char filepath[512];
                snprintf(filepath, sizeof(filepath), "/etc/.enc_config/%s", entry->d_name);
                FILE *fp = fopen(filepath, "r");
                if (fp) {
                    char file_content[8192];
                    memset(file_content, 0, sizeof(file_content));
                    if (fgets(file_content, sizeof(file_content) - 1, fp) != NULL) {
                        size_t flen = strlen(file_content);
                        while (flen > 0 && (file_content[flen - 1] == '\r' || file_content[flen - 1] == '\n' || file_content[flen - 1] == ' ')) {
                            file_content[flen - 1] = '\0';
                            flen--;
                        }
                        if (strcmp(file_content, clean_obf) == 0) {
                            fclose(fp);
                            closedir(dir);
                            
                            unsigned char raw_pub[4096];
                            size_t raw_pub_len = 0;
                            trf_base64_decode_obfuscated(clean_obf, fingerprint, raw_pub, &raw_pub_len);

                            char *plain_b64_pub = malloc(8192);
                            memset(plain_b64_pub, 0, 8192);
                            trf_base64_encode(raw_pub, raw_pub_len, plain_b64_pub);
                            
                            fprintf(stderr, "[PQC-HS] Found matching peer pub key file on disk. De-obfuscated peer pub key using fingerprint [%s].\n", fingerprint);
                            return plain_b64_pub;
                        }
                    }
                    fclose(fp);
                }
            }
        }
        closedir(dir);
    }

    // Method 2: Check registry to see if we already have a fingerprint that matches (Fallback)
    for (int i = 0; i < g_registry_count; i++) {
        unsigned char raw_pub[4096];
        size_t raw_pub_len = 0;
        trf_base64_decode_obfuscated(clean_obf, g_identity_registry[i].fingerprint, raw_pub, &raw_pub_len);

        char plain_b64_pub[8192];
        memset(plain_b64_pub, 0, sizeof(plain_b64_pub));
        trf_base64_encode(raw_pub, raw_pub_len, plain_b64_pub);

        if (strcmp(plain_b64_pub, g_identity_registry[i].pub_key) == 0) {
            fprintf(stderr, "[PQC-HS] Found matching peer pub key in RAM Registry. De-obfuscated peer pub key using fingerprint [%s].\n", g_identity_registry[i].fingerprint);
            return strdup(plain_b64_pub);
        }
    }

    // Fallback: If we couldn't de-obfuscate it, return the original string
    fprintf(stderr, "[PQC-HS] Warning: Could not find matching fingerprint for peer public key. Using original string.\n");
    return strdup(obf_pub_str);
}

void sig_pqc_set_peer_identity(const char *pub, const char *peer_fingerprint) {
    char *deobf = pub ? deobfuscate_peer_pub(pub, peer_fingerprint) : NULL;

    pthread_mutex_lock(&g_key_mutex);
    if (g_peer_id_pub) free(g_peer_id_pub);
    g_peer_id_pub = deobf;
    pthread_mutex_unlock(&g_key_mutex);

    if (g_peer_id_pub) fprintf(stderr, "[PQC-HS] Peer identity key loaded and de-obfuscated. Ready for Handshake.\n");
}

bool sig_pqc_has_identity(const char *fingerprint) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            pthread_mutex_unlock(&g_key_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return false;
}

void sig_pqc_bind_profile_keys(int profile_id, const char *local_priv, const char *local_pub, const char *peer_pub, const char *peer_fingerprint) {
    char *deobf_peer = peer_pub ? deobfuscate_peer_pub(peer_pub, peer_fingerprint) : NULL;

    pthread_mutex_lock(&g_key_mutex);
    
    // Check if already bound
    for (int i = 0; i < g_profile_bindings_count; i++) {
        if (g_profile_bindings[i].profile_id == profile_id) {
            if (g_profile_bindings[i].local_priv) free(g_profile_bindings[i].local_priv);
            if (g_profile_bindings[i].local_pub) free(g_profile_bindings[i].local_pub);
            if (g_profile_bindings[i].peer_pub) free(g_profile_bindings[i].peer_pub);
            
            g_profile_bindings[i].local_priv = local_priv ? strdup(local_priv) : NULL;
            g_profile_bindings[i].local_pub = local_pub ? strdup(local_pub) : NULL;
            g_profile_bindings[i].peer_pub = deobf_peer;
            
            pthread_mutex_unlock(&g_key_mutex);
            return;
        }
    }
    
    if (g_profile_bindings_count < MAX_IDENTITY_REGISTRY) {
        profile_key_binding_t *b = &g_profile_bindings[g_profile_bindings_count++];
        b->profile_id = profile_id;
        b->local_priv = local_priv ? strdup(local_priv) : NULL;
        b->local_pub = local_pub ? strdup(local_pub) : NULL;
        b->peer_pub = deobf_peer;
        fprintf(stderr, "[PQC-BIND] Profile %d bound to Local/Peer keys in RAM.\n", profile_id);
    }
    
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_get_profile_keys(int profile_id, char **out_local_priv, char **out_local_pub, char **out_peer_pub) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_profile_bindings_count; i++) {
        if (g_profile_bindings[i].profile_id == profile_id) {
            if (out_local_priv) *out_local_priv = g_profile_bindings[i].local_priv;
            if (out_local_pub) *out_local_pub = g_profile_bindings[i].local_pub;
            if (out_peer_pub) *out_peer_pub = g_profile_bindings[i].peer_pub;
            pthread_mutex_unlock(&g_key_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
}

int sig_pqc_find_identity(const char *fingerprint, char **out_priv, char **out_pub) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            if (out_priv) *out_priv = g_identity_registry[i].priv_key;
            if (out_pub) *out_pub = g_identity_registry[i].pub_key;
            pthread_mutex_unlock(&g_key_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
}

void sig_pqc_load_keys_from_disk(void) {
    DIR *dir = opendir("/dev/shm/.enc_config");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "identity_", 9) == 0 && strstr(entry->d_name, "_priv.key") != NULL) {
            char fingerprint[16];
            memset(fingerprint, 0, sizeof(fingerprint));
            strncpy(fingerprint, entry->d_name + 9, 8);

            char priv_path[512];
            char pub_path[512];
            snprintf(priv_path, sizeof(priv_path), "/dev/shm/.enc_config/%s", entry->d_name);
            snprintf(pub_path, sizeof(pub_path), "/etc/.enc_config/identity_%s_pub.key", fingerprint);

            FILE *fp_priv = fopen(priv_path, "r");
            if (!fp_priv) continue;
            char obf_priv[8192];
            memset(obf_priv, 0, sizeof(obf_priv));
            if (fgets(obf_priv, sizeof(obf_priv) - 1, fp_priv) == NULL) {
                fclose(fp_priv);
                continue;
            }
            fclose(fp_priv);
            obf_priv[strcspn(obf_priv, "\r\n")] = '\0';

            FILE *fp_pub = fopen(pub_path, "r");
            if (!fp_pub) continue;
            char obf_pub[4096];
            memset(obf_pub, 0, sizeof(obf_pub));
            if (fgets(obf_pub, sizeof(obf_pub) - 1, fp_pub) == NULL) {
                fclose(fp_pub);
                continue;
            }
            fclose(fp_pub);
            obf_pub[strcspn(obf_pub, "\r\n")] = '\0';

            unsigned char raw_priv[4096];
            size_t raw_priv_len = 0;
            trf_base64_decode_obfuscated(obf_priv, fingerprint, raw_priv, &raw_priv_len);

            char plain_b64_priv[8192];
            memset(plain_b64_priv, 0, sizeof(plain_b64_priv));
            trf_base64_encode(raw_priv, raw_priv_len, plain_b64_priv);

            unsigned char raw_pub[4096];
            size_t raw_pub_len = 0;
            trf_base64_decode_obfuscated(obf_pub, fingerprint, raw_pub, &raw_pub_len);

            char plain_b64_pub[8192];
            memset(plain_b64_pub, 0, sizeof(plain_b64_pub));
            trf_base64_encode(raw_pub, raw_pub_len, plain_b64_pub);

            sig_pqc_add_to_registry(fingerprint, plain_b64_priv, plain_b64_pub);
            fprintf(stderr, "[PQC-LOAD] Loaded Local Identity Fingerprint [%s] from secure RAM-disk (/dev/shm) into RAM.\n", fingerprint);
        }
    }
    closedir(dir);
}
