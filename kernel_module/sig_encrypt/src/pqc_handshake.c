#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include "../inc/pqc_logger.h"
#include <sys/stat.h>
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

#define PQC_RX_PKT_MAX     10000
#define KEY_ROTATION_INTERVAL_MS 30000 
#define PQC_HS_GIVEUP_TIMEOUT_MS 15000

extern void sig_pqc_on_key_ready(int profile_id, const uint8_t *key_bytes);

__attribute__((weak)) void forwarder_pre_diversify_pqc_keys(int profile_id) {
    (void)profile_id;
}

static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static identity_entry_t g_identity_registry[MAX_IDENTITY_REGISTRY];
static int g_registry_count = 0;

static policy_key_binding_t g_policy_bindings[MAX_POLICY_BINDINGS];
static int g_policy_bindings_count = 0;
static volatile int g_policy_key_version[MAX_POLICY_BINDINGS] = {0};
static volatile int g_datapath_key_version[MAX_POLICY_BINDINGS] = {0};
static bool g_policy_bindings_active[MAX_POLICY_BINDINGS] = {false};

static bool g_dispatcher_running = false;

static int pqc_policy_rx_recv(policy_key_binding_t *b, uint8_t *buf, int buf_sz, pqc_rx_pkt_info_t *info, int timeout_ms);

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

static uint64_t get_time_ms_hs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void handle_handshake_success(policy_key_binding_t *b, const uint8_t *derived_master, const char *role) {
    if (b->key_ready) {
        sig_pqc_write_log(b->profile_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Session key updated.");
    } else {
        sig_pqc_write_log(b->profile_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Secure session established.");
    }

    memcpy(b->keys[KEY_SLOT_PREV], b->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    b->key_ids[KEY_SLOT_PREV] = b->key_ids[KEY_SLOT_CURRENT];
    b->key_slots_valid[KEY_SLOT_PREV] = b->key_slots_valid[KEY_SLOT_CURRENT];

    memcpy(b->keys[KEY_SLOT_CURRENT], derived_master, PQC_TRAFFIC_KEY_SZ);
    b->key_ids[KEY_SLOT_CURRENT] = (b->key_ids[KEY_SLOT_CURRENT] + 1) & 0xFF;
    if (b->key_ids[KEY_SLOT_CURRENT] == 0) b->key_ids[KEY_SLOT_CURRENT] = 1;
    b->key_slots_valid[KEY_SLOT_CURRENT] = true;

    b->key_slots_valid[KEY_SLOT_NEXT] = false;

    memcpy(b->encrypt_key, derived_master, PQC_TRAFFIC_KEY_SZ);
    memcpy(b->decrypt_key, derived_master, PQC_TRAFFIC_KEY_SZ);

    b->key_ready = true;
    b->last_sent_time = get_time_ms_hs();
    b->last_recv_time = get_time_ms_hs();
    b->last_rotation_time = get_time_ms_hs();
    b->handshake_start_time = 0;
    b->handshake_give_up = false;
    b->rotation_start_time = 0;
    b->rotation_give_up = false;

    int idx = b - g_policy_bindings;
    if (idx >= 0 && idx < MAX_POLICY_BINDINGS) {
        g_policy_key_version[idx]++;
    }

    fprintf(stderr, "[PQC-HS] %s Handshake SUCCESS for Profile %d. Promoted new key ID: %d to CURRENT. Key prefix: %02X%02X%02X%02X...\n",
            role, b->profile_id, b->key_ids[KEY_SLOT_CURRENT],
            derived_master[0], derived_master[1], derived_master[2], derived_master[3]);

    // Call success callback to synchronize the key to the kernel datapath
    sig_pqc_on_key_ready(b->profile_id, derived_master);
}

static void initiate_key_rotation(policy_key_binding_t *b, int sockfd, struct sockaddr_in *peeraddr, char *my_priv, char *peer_pub, int profile_id) {
    fprintf(stderr, "[PQC-HS-L3] Proactively initiating periodic key rotation for Profile %d...\n", b->profile_id);

    uint8_t pk[2048], sk[4096], ss[128];
    int pk_sz = 0, sk_sz = 0;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] KEM keygen failed during rotation!\n");
        return;
    }

    uint32_t msg_id = (uint32_t)rand();
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_HELLO;
    msg->session_id = msg_id;
    msg->profile_id = b->profile_id;
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

    int payload_tot_sz = sizeof(struct pqc_hs_msg) + pk_sz + sig_sz;
    sendto(sockfd, buffer, payload_tot_sz, 0, (const struct sockaddr *)peeraddr, sizeof(struct sockaddr_in));

    uint64_t start_rx = get_time_ms_hs();
    while (g_dispatcher_running && get_time_ms_hs() - start_rx < 3000) {
        uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
        pqc_rx_pkt_info_t info;
        int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
        if (rx_len > 0) {
            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)rx_buf;
            if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP && resp->session_id == msg_id) {
                pthread_mutex_lock(&g_key_mutex);
                size_t raw_pub_sz = 0;
                uint8_t raw_pub[8192];
                trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                pthread_mutex_unlock(&g_key_mutex);

                if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, resp->payload, resp->data_len, resp->payload + resp->data_len, resp->sig_len) == TRF_PQC_OK) {
                    if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                        derive_traffic_key(ss, 32, derived_master);

                        pthread_mutex_lock(&g_key_mutex);
                        handle_handshake_success(b, derived_master, "Initiator");
                        pthread_mutex_unlock(&g_key_mutex);

                        forwarder_pre_diversify_pqc_keys(profile_id);
                        return;
                    }
                }
            }
        }
        usleep(10000);
    }
    fprintf(stderr, "[PQC-HS-L3] Key rotation handshake attempt timed out or failed for Profile %d.\n", b->profile_id);
}

static void pqc_feed_packet_to_binding_queue(policy_key_binding_t *b, const uint8_t *data, int len) {
    pthread_mutex_lock(&b->rx_mutex);
    int next = (b->rx_head + 1) % PQC_RX_QUEUE_SIZE;
    if (next != b->rx_tail) {
        if (b->rx_queue[b->rx_head]) {
            free(b->rx_queue[b->rx_head]);
        }
        b->rx_queue[b->rx_head] = malloc(len);
        if (b->rx_queue[b->rx_head]) {
            memcpy(b->rx_queue[b->rx_head], data, len);
            b->rx_len[b->rx_head] = len;
            b->rx_head = next;
            pthread_cond_signal(&b->rx_cond);
        }
    }
    pthread_mutex_unlock(&b->rx_mutex);
}

void sig_pqc_feed_rx_packet(const uint8_t *payload, int len, const uint8_t *src_mac) {
    (void)src_mac;
    if (len < (int)sizeof(struct pqc_hs_msg)) return;
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)payload;
    if (msg->magic != PQC_HS_MAGIC) return;

    uint32_t profile_id = msg->profile_id;
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == (int)profile_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            if (msg->msg_type == PQC_HS_MSG_POKE) {
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->key_ready = false;
                fprintf(stderr, "[PQC-HS] Received POKE message. Resetting handshake retry for Profile %d.\n", profile_id);
                pthread_mutex_unlock(&g_key_mutex);
                return;
            } else if (msg->msg_type == PQC_HS_MSG_HELLO) {
                if (b->handshake_give_up) {
                    b->handshake_give_up = false;
                    b->handshake_start_time = 0;
                    b->rotation_give_up = false;
                    b->rotation_start_time = 0;
                    b->key_ready = false;
                    fprintf(stderr, "[PQC-HS] Received HELLO message while asleep. Waking up Responder for Profile %d.\n", profile_id);
                }
            }
            pqc_feed_packet_to_binding_queue(b, payload, len);
            pthread_mutex_unlock(&g_key_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

static int pqc_policy_rx_recv(policy_key_binding_t *b, uint8_t *buf, int buf_sz, pqc_rx_pkt_info_t *info, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&b->rx_mutex);
    while (b->rx_head == b->rx_tail) {
        if (pthread_cond_timedwait(&b->rx_cond, &b->rx_mutex, &ts) != 0) {
            pthread_mutex_unlock(&b->rx_mutex);
            return -1; // timeout
        }
    }
    int len = b->rx_len[b->rx_tail];
    if (len > buf_sz) len = buf_sz;
    memcpy(buf, b->rx_queue[b->rx_tail], len);
    if (info) {
        info->src_addr = b->rx_info[b->rx_tail].src_addr;
        memcpy(info->src_mac, b->rx_info[b->rx_tail].src_mac, 6);
    }
    free(b->rx_queue[b->rx_tail]);
    b->rx_queue[b->rx_tail] = NULL;
    b->rx_len[b->rx_tail] = 0;
    b->rx_tail = (b->rx_tail + 1) % PQC_RX_QUEUE_SIZE;
    pthread_mutex_unlock(&b->rx_mutex);
    return len;
}

static void* pqc_udp_dispatcher_thread(void* arg) {
    (void)arg;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[PQC-DISPATCHER] Socket creation failed");
        return NULL;
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PQC_HS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("[PQC-DISPATCHER] Bind failed (Port 7090)");
        close(sockfd);
        return NULL;
    }

    uint8_t buffer[PQC_HS_MSG_MAX_SZ];
    struct sockaddr_in clientaddr;
    socklen_t addr_len = sizeof(clientaddr);

    fprintf(stderr, "[PQC-DISPATCHER] UDP Listener running on port %d\n", PQC_HS_PORT);

    while (g_dispatcher_running) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addr_len);
        if (n > 0) {
            sig_pqc_feed_rx_packet(buffer, n, NULL);
        } else {
            usleep(10000);
        }
    }

    close(sockfd);
    return NULL;
}

static void* pqc_policy_handshake_worker_run(void *arg) {
    policy_key_binding_t *b = (policy_key_binding_t *)arg;
    int profile_id = b->profile_id;

    fprintf(stderr, "[PQC-WORKER] Handshake Worker started for Profile %d\n", profile_id);

    pthread_mutex_lock(&g_key_mutex);
    char *my_priv = b->local_priv ? strdup(b->local_priv) : NULL;
    char *my_pub = b->local_pub ? strdup(b->local_pub) : NULL;
    char *peer_pub = b->peer_pub ? strdup(b->peer_pub) : NULL;
    bool is_initiator = b->is_initiator;
    char wan_ifname[64];
    strncpy(wan_ifname, b->wan_ifname, sizeof(wan_ifname) - 1);
    wan_ifname[sizeof(wan_ifname) - 1] = '\0';
    char peer_ip[64];
    strncpy(peer_ip, b->peer_ip, sizeof(peer_ip) - 1);
    peer_ip[sizeof(peer_ip) - 1] = '\0';
    pthread_mutex_unlock(&g_key_mutex);

    if (!my_priv || !my_pub || !peer_pub) {
        fprintf(stderr, "[PQC-WORKER] Profile %d error: local or peer keys not configured.\n", profile_id);
        if (my_priv) free(my_priv);
        if (my_pub) free(my_pub);
        if (peer_pub) free(peer_pub);
        pthread_mutex_lock(&g_key_mutex);
        b->thread_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return NULL;
    }

    const char *initial_role = (b->role_mode == PQC_ROLE_INITIATOR) ? "INITIATOR" :
                               (b->role_mode == PQC_ROLE_RESPONDER) ? "RESPONDER" : "DYNAMIC (resolving...)";
    fprintf(stderr, "[PQC-WORKER] Profile %d keys loaded. Starting L3 state machine (role: %s)\n",
            profile_id, initial_role);

    uint8_t pk[2048], sk[4096], ct[2048], ss[128];
    int pk_sz = 0, sk_sz = 0, ct_sz = 0;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[PQC-WORKER] UDP Socket creation failed");
        free(my_priv); free(my_pub); free(peer_pub);
        pthread_mutex_lock(&g_key_mutex);
        b->thread_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return NULL;
    }

    struct sockaddr_in peeraddr;
    memset(&peeraddr, 0, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(PQC_HS_PORT);
    inet_pton(AF_INET, peer_ip, &peeraddr.sin_addr);

    while (g_dispatcher_running && !b->thread_exit_sig) {
        if (b->handshake_give_up) {
            usleep(500000);
            continue;
        }
        if (!b->key_ready) {
            if (b->role_mode == PQC_ROLE_DYNAMIC) {
                int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (temp_sock >= 0) {
                    struct sockaddr_in serv;
                    memset(&serv, 0, sizeof(serv));
                    serv.sin_family = AF_INET;
                    serv.sin_addr.s_addr = inet_addr(peer_ip);
                    serv.sin_port = htons(PQC_HS_PORT);

                    bool resolved = false;
                    uint32_t local_ip_num = 0;
                    char local_ip_str[32] = "0.0.0.0";

                    if (strlen(b->wan_ifname) > 0) {
                        struct ifreq ifr;
                        memset(&ifr, 0, sizeof(ifr));
                        strncpy(ifr.ifr_name, b->wan_ifname, IFNAMSIZ - 1);
                        ifr.ifr_addr.sa_family = AF_INET;
                        if (ioctl(temp_sock, SIOCGIFADDR, &ifr) == 0) {
                            struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
                            local_ip_num = ntohl(ipaddr->sin_addr.s_addr);
                            strncpy(local_ip_str, inet_ntoa(ipaddr->sin_addr), sizeof(local_ip_str) - 1);
                            resolved = true;
                        }
                    }
                    close(temp_sock);

                    if (resolved) {
                        uint32_t peer_ip_num = ntohl(serv.sin_addr.s_addr);
                        if (local_ip_num > peer_ip_num) {
                            is_initiator = true;
                        } else {
                            is_initiator = false;
                        }
                        fprintf(stderr, "[PQC-WORKER-L3] Profile %d: Dynamic role resolved. Local IP: %s (%u), Peer IP: %s (%u). Resolved Role: %s\n",
                                profile_id, local_ip_str, local_ip_num, peer_ip, peer_ip_num,
                                is_initiator ? "INITIATOR" : "RESPONDER");
                    }
                }
            }

            if (is_initiator) {
                if (b->handshake_start_time == 0) {
                    b->handshake_start_time = get_time_ms_hs();
                }

                trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz);
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                msg->magic = PQC_HS_MAGIC;
                msg->msg_type = PQC_HS_MSG_HELLO;
                msg->session_id = 123;
                msg->profile_id = profile_id;
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

                int retry_cnt = 0;
                while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = get_time_ms_hs();
                        retry_cnt = 0;
                    }
                    if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                        fprintf(stderr, "[PQC-HS-L3] Handshake timed out after %d seconds. Giving up on Profile %d.\n",
                                PQC_HS_GIVEUP_TIMEOUT_MS / 1000, profile_id);
                        sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Peer connection timeout.");
                        b->handshake_give_up = true;
                        break;
                    }
                    fprintf(stderr, "[PQC-WORKER-L3] Initiator (Profile %d) sending HELLO (try: %d)...\n", profile_id, retry_cnt + 1);
                    sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz + sig_sz, 0,
                           (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                    uint64_t start_rx = get_time_ms_hs();
                    while (g_dispatcher_running && get_time_ms_hs() - start_rx < 3000 && !b->key_ready && !b->thread_exit_sig) {
                        uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                        pqc_rx_pkt_info_t info;
                        int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                        if (rx_len > 0) {
                            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)rx_buf;
                            if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                                pthread_mutex_lock(&g_key_mutex);
                                size_t raw_pub_sz = 0;
                                uint8_t raw_pub[8192];
                                trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                                pthread_mutex_unlock(&g_key_mutex);

                                if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, resp->payload, resp->data_len, resp->payload + resp->data_len, resp->sig_len) == TRF_PQC_OK) {
                                    if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                        derive_traffic_key(ss, 32, derived_master);

                                        pthread_mutex_lock(&g_key_mutex);
                                        handle_handshake_success(b, derived_master, "Initiator");
                                        pthread_mutex_unlock(&g_key_mutex);

                                        fprintf(stderr, "[PQC-WORKER-L3] Handshake SUCCESS for Profile %d!\n", profile_id);
                                        forwarder_pre_diversify_pqc_keys(profile_id);
                                        break;
                                    }
                                }
                            }
                        }
                        usleep(10000);
                    }
                    retry_cnt++;
                }
            } else {
                if (b->handshake_start_time == 0) {
                    b->handshake_start_time = get_time_ms_hs();
                }
                fprintf(stderr, "[PQC-WORKER-L3] Responder (Profile %d) listening for HELLO...\n", profile_id);
                while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = get_time_ms_hs();
                    }
                    if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                        fprintf(stderr, "[PQC-HS-L3] Responder timed out waiting for HELLO on Profile %d.\n", profile_id);
                        sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake timeout. No HELLO received from Peer.");
                        b->handshake_give_up = true;
                        break;
                    }
                    pthread_mutex_lock(&g_key_mutex);
                    if (b->send_poke) {
                        b->send_poke = false;
                        pthread_mutex_unlock(&g_key_mutex);
                        struct pqc_hs_msg poke_msg;
                        poke_msg.magic = PQC_HS_MAGIC;
                        poke_msg.msg_type = PQC_HS_MSG_POKE;
                        poke_msg.session_id = 999;
                        poke_msg.profile_id = profile_id;
                        poke_msg.sig_len = 0;
                        poke_msg.data_len = 0;
                        fprintf(stderr, "[PQC-WORKER-L3] Responder (Profile %d) sending POKE to Initiator...\n", profile_id);
                        sendto(sockfd, &poke_msg, sizeof(poke_msg), 0, (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
                    } else {
                        pthread_mutex_unlock(&g_key_mutex);
                    }

                    uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                    pqc_rx_pkt_info_t info;
                    int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                    if (rx_len > 0) {
                        struct pqc_hs_msg *msg = (struct pqc_hs_msg *)rx_buf;
                        if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                            pthread_mutex_lock(&g_key_mutex);
                            size_t raw_pub_sz = 0;
                            uint8_t raw_pub[8192];
                            trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                            pthread_mutex_unlock(&g_key_mutex);

                            if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                                if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                                    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                                    resp->magic = PQC_HS_MAGIC;
                                    resp->msg_type = PQC_HS_MSG_RESP;
                                    resp->session_id = msg->session_id;
                                    resp->profile_id = profile_id;
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
                                    handle_handshake_success(b, derived_master, "Responder");
                                    pthread_mutex_unlock(&g_key_mutex);

                                    forwarder_pre_diversify_pqc_keys(profile_id);
                                } else {
                                    fprintf(stderr, "[PQC-HS-L3] Handshake signature verification failed for Profile %d. Mismatched authentication keys or packet corrupted.\n", profile_id);
                                    sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake signature verification failed. Mismatched authentication keys.");
                                }
                            }
                        }
                    }
                    usleep(10000);
                }
            }
        } else {
            if (is_initiator) {
                uint64_t now = get_time_ms_hs();
                if (b->last_sent_time > 0 && (now - b->last_sent_time < 10000) && (now - b->last_recv_time > 15000)) {
                    fprintf(stderr, "[PQC-HS-L3] Self-healing triggered (Initiator): active TX but no RX. Resetting key for Profile %d.\n", profile_id);
                    pthread_mutex_lock(&g_key_mutex);
                    b->key_ready = false;
                    b->last_sent_time = 0;
                    b->last_recv_time = 0;
                    pthread_mutex_unlock(&g_key_mutex);
                } else if (now - b->last_rotation_time > KEY_ROTATION_INTERVAL_MS) {
                    if (!b->rotation_give_up) {
                        if (b->rotation_start_time == 0) {
                            b->rotation_start_time = now;
                        }
                        if (now - b->rotation_start_time > 15000) {
                            fprintf(stderr, "[PQC-HS-L3] Key rotation timed out after 15 seconds. Giving up on Profile %d.\n", profile_id);
                            sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed.");
                            pthread_mutex_lock(&g_key_mutex);
                            b->key_ready = false;
                            b->handshake_give_up = true;
                            b->rotation_start_time = 0;
                            b->rotation_give_up = false;
                            pthread_mutex_unlock(&g_key_mutex);
                        } else {
                            initiate_key_rotation(b, sockfd, &peeraddr, my_priv, peer_pub, profile_id);
                        }
                    }
                }
                usleep(500000);
            } else {
                uint64_t now = get_time_ms_hs();
                if (!b->rotation_give_up && (now - b->last_rotation_time > KEY_ROTATION_INTERVAL_MS + 15000)) {
                    fprintf(stderr, "[PQC-HS-L3] Key rotation timed out on Responder side (Profile %d). No HELLO received from Peer.\n", profile_id);
                    sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed. No handshake request received from Peer.");
                    pthread_mutex_lock(&g_key_mutex);
                    b->key_ready = false;
                    b->handshake_give_up = true;
                    b->rotation_give_up = false;
                    pthread_mutex_unlock(&g_key_mutex);
                }

                uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                pqc_rx_pkt_info_t info;
                int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                if (rx_len > 0) {
                    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)rx_buf;
                    if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                        fprintf(stderr, "[PQC-HS-L3] Responder received HELLO while ONLINE. Peer might have restarted! Re-handshaking for Profile %d...\n", profile_id);

                        pthread_mutex_lock(&g_key_mutex);
                        size_t raw_pub_sz = 0;
                        uint8_t raw_pub[8192];
                        trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                        pthread_mutex_unlock(&g_key_mutex);

                        if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                            if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                                struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                                resp->magic = PQC_HS_MAGIC;
                                resp->msg_type = PQC_HS_MSG_RESP;
                                resp->session_id = msg->session_id;
                                resp->profile_id = profile_id;
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
                                handle_handshake_success(b, derived_master, "Responder");
                                pthread_mutex_unlock(&g_key_mutex);

                                forwarder_pre_diversify_pqc_keys(profile_id);
                            } else {
                                fprintf(stderr, "[PQC-HS-L3] Handshake signature verification failed for Profile %d (Online state). Mismatched authentication keys or packet corrupted.\n", profile_id);
                                sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake signature verification failed. Mismatched authentication keys.");
                            }
                        }
                    } else if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_KEEPALIVE) {
                        fprintf(stderr, "[PQC-HS-L3] Responder received KEEPALIVE for Profile %d. Verifying signature...\n", profile_id);
                        pthread_mutex_lock(&g_key_mutex);
                        size_t raw_pub_sz = 0;
                        uint8_t raw_pub[8192];
                        trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                        pthread_mutex_unlock(&g_key_mutex);

                        if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                            fprintf(stderr, "[PQC-HS-L3] Keepalive verified successfully! Promoting responder key.\n");
                            sig_pqc_promote_responder_key(profile_id);
                        } else {
                            fprintf(stderr, "[PQC-HS-L3] Keepalive signature verification failed!\n");
                        }
                    }
                }
                usleep(10000);
            }
        }
    }
    close(sockfd);
    free(my_priv);
    free(my_pub);
    free(peer_pub);
    pthread_mutex_lock(&g_key_mutex);
    b->thread_started = false;
    pthread_mutex_unlock(&g_key_mutex);
    return NULL;
}

int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip) {
    pthread_mutex_lock(&g_key_mutex);
    if (!g_dispatcher_running) {
        g_dispatcher_running = true;
        pthread_t udp_tid;
        if (pthread_create(&udp_tid, NULL, pqc_udp_dispatcher_thread, NULL) == 0) {
            pthread_detach(udp_tid);
        } else {
            fprintf(stderr, "[PQC-HS] ERROR starting UDP dispatcher thread\n");
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            if (wan_ifname && wan_ifname[0] != '\0') {
                strncpy(g_policy_bindings[i].wan_ifname, wan_ifname, sizeof(g_policy_bindings[i].wan_ifname) - 1);
                g_policy_bindings[i].wan_ifname[sizeof(g_policy_bindings[i].wan_ifname) - 1] = '\0';
            }
            if (peer_ip && peer_ip[0] != '\0') {
                strncpy(g_policy_bindings[i].peer_ip, peer_ip, sizeof(g_policy_bindings[i].peer_ip) - 1);
                g_policy_bindings[i].peer_ip[sizeof(g_policy_bindings[i].peer_ip) - 1] = '\0';
            }
            if (!g_policy_bindings[i].thread_started) {
                g_policy_bindings[i].thread_started = true;
                if (pthread_create(&g_policy_bindings[i].thread_id, NULL, pqc_policy_handshake_worker_run, &g_policy_bindings[i]) == 0) {
                    pthread_detach(g_policy_bindings[i].thread_id);
                    fprintf(stderr, "[PQC-HS] Spawned Handshake Worker for Profile %d\n", profile_id);
                } else {
                    g_policy_bindings[i].thread_started = false;
                    fprintf(stderr, "[PQC-HS] ERROR: Failed to spawn Handshake Worker for Profile %d\n", profile_id);
                }
            }
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    return 0;
}

bool sig_pqc_is_key_ready(void) {
    pthread_mutex_lock(&g_key_mutex);
    bool ready = false;
    if (g_policy_bindings_count > 0) {
        ready = g_policy_bindings[0].key_ready;
    }
    pthread_mutex_unlock(&g_key_mutex);
    return ready;
}

int sig_pqc_get_traffic_key(uint8_t out_key[PQC_TRAFFIC_KEY_SZ]) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_policy_bindings_count == 0 || !g_policy_bindings[0].key_ready) {
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    memcpy(out_key, g_policy_bindings[0].encrypt_key, PQC_TRAFFIC_KEY_SZ);
    pthread_mutex_unlock(&g_key_mutex);
    return 0;
}

int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key) {
    (void)policy_id;
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            if (g_policy_bindings[i].key_ready) {
                memcpy(out_policy_key, g_policy_bindings[i].encrypt_key, PQC_TRAFFIC_KEY_SZ);
                pthread_mutex_unlock(&g_key_mutex);
                return 0;
            } else {
                pthread_mutex_unlock(&g_key_mutex);
                return -1;
            }
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
}

void sig_pqc_add_to_registry(const char *fingerprint, const char *priv, const char *pub) {
    if (!fingerprint || !priv || !pub) return;
    pthread_mutex_lock(&g_key_mutex);
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
    if (g_registry_count < MAX_IDENTITY_REGISTRY) {
        strncpy(g_identity_registry[g_registry_count].fingerprint, fingerprint, 15);
        g_identity_registry[g_registry_count].fingerprint[15] = '\0';
        g_identity_registry[g_registry_count].priv_key = strdup(priv);
        g_identity_registry[g_registry_count].pub_key = strdup(pub);
        g_registry_count++;
    }
    pthread_mutex_unlock(&g_key_mutex);
}

char* sig_pqc_deobfuscate_peer_pub(const char *obf_pub_str, const char *peer_fingerprint) {
    if (!obf_pub_str) return NULL;
    
    // Remote suffix '.key' if present in peer_fingerprint
    char clean_fg[16] = "";
    if (peer_fingerprint) {
        strncpy(clean_fg, peer_fingerprint, 8);
        clean_fg[8] = '\0';
    }

    const char *clean_obf = obf_pub_str;
    if (strncmp(obf_pub_str, clean_fg, strlen(clean_fg)) == 0) {
        clean_obf = obf_pub_str + strlen(clean_fg);
    }

    // Method 1: Scan /etc/.dec_config/ for matching public key file to get fingerprint (Fallback)
    DIR *dir = opendir("/etc/.dec_config");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            size_t name_len = strlen(entry->d_name);
            if (name_len == 12 && strcmp(entry->d_name + 8, ".key") == 0) {
                char fingerprint[16];
                memset(fingerprint, 0, sizeof(fingerprint));
                strncpy(fingerprint, entry->d_name, 8);

                char filepath[512];
                snprintf(filepath, sizeof(filepath), "/etc/.dec_config/%s", entry->d_name);
                FILE *fp = fopen(filepath, "r");
                if (fp) {
                    char file_content[8192];
                    memset(file_content, 0, sizeof(file_content));
                    if (fgets(file_content, sizeof(file_content) - 1, fp) != NULL) {
                        file_content[strcspn(file_content, "\r\n")] = '\0';
                        if (strncmp(file_content, fingerprint, 8) == 0) {
                            const char *obf_pub = file_content + 8;
                            if (strcmp(obf_pub, clean_obf) == 0) {
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

void sig_pqc_bind_profile(int profile_id, int role_mode,
                          const char *peer_ip, const char *local_fg,
                          const char *peer_fg, const char *wan_ifname,
                          const char *local_priv, const char *local_pub,
                          const char *peer_pub) {
    char *deobf_peer = peer_pub ? strdup(peer_pub) : NULL;

    pthread_mutex_lock(&g_key_mutex);
    policy_key_binding_t *b = NULL;
    bool is_existing = false;
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            b = &g_policy_bindings[i];
            is_existing = true;
            break;
        }
    }
    if (!b && g_policy_bindings_count < MAX_POLICY_BINDINGS) {
        b = &g_policy_bindings[g_policy_bindings_count++];
        memset(b->encrypt_key, 0, PQC_TRAFFIC_KEY_SZ);
        memset(b->decrypt_key, 0, PQC_TRAFFIC_KEY_SZ);
        b->key_ready = false;
        b->thread_started = false;
        b->rx_head = 0;
        b->rx_tail = 0;
        pthread_mutex_init(&b->rx_mutex, NULL);
        pthread_cond_init(&b->rx_cond, NULL);
        for (int j = 0; j < PQC_RX_QUEUE_SIZE; j++) {
            b->rx_queue[j] = NULL;
            b->rx_len[j] = 0;
        }
        b->local_priv = NULL;
        b->local_pub = NULL;
        b->peer_pub = NULL;

        // Initialize 3-slot metadata
        b->last_rotation_time = get_time_ms_hs();
        b->last_sent_time = 0;
        b->last_recv_time = 0;
        b->handshake_start_time = 0;
        b->handshake_give_up = false;
        b->rotation_start_time = 0;
        b->rotation_give_up = false;
        b->send_poke = false;
        b->thread_exit_sig = false;
        for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
            memset(b->keys[slot], 0, PQC_TRAFFIC_KEY_SZ);
            b->key_ids[slot] = 0;
            b->key_slots_valid[slot] = false;
        }
    }
    if (b) {
        if (is_existing) {
            bool changed = false;
            if (b->local_priv && local_priv && strcmp(b->local_priv, local_priv) != 0) changed = true;
            if (b->local_pub && local_pub && strcmp(b->local_pub, local_pub) != 0) changed = true;
            if (b->peer_pub && deobf_peer && strcmp(b->peer_pub, deobf_peer) != 0) changed = true;
            
            if ((b->local_priv == NULL) != (local_priv == NULL)) changed = true;
            if ((b->local_pub == NULL) != (local_pub == NULL)) changed = true;
            if ((b->peer_pub == NULL) != (deobf_peer == NULL)) changed = true;

            if (strcmp(b->peer_ip, peer_ip ? peer_ip : "") != 0) changed = true;
            if (strcmp(b->wan_ifname, wan_ifname ? wan_ifname : "") != 0) changed = true;
            if (b->role_mode != role_mode) changed = true;

            if (changed) {
                fprintf(stderr, "[PQC-BIND-DBG] Profile %d: change detected, thread_started=%d, about to wait for worker exit...\n",
                        profile_id, (int)b->thread_started);
                if (b->thread_started) {
                    uint64_t wait_start = get_time_ms_hs();
                    b->thread_exit_sig = true;
                    int wait_iters = 0;
                    while (b->thread_started) {
                        pthread_mutex_unlock(&g_key_mutex);
                        usleep(1000);
                        pthread_mutex_lock(&g_key_mutex);
                        wait_iters++;
                        if (wait_iters % 500 == 0) {
                            fprintf(stderr, "[PQC-BIND-DBG] Profile %d: STILL waiting for worker exit... (%dms elapsed)\n",
                                    profile_id, (int)(get_time_ms_hs() - wait_start));
                        }
                    }
                    fprintf(stderr, "[PQC-BIND-DBG] Profile %d: worker exited after %dms. Proceeding.\n",
                            profile_id, (int)(get_time_ms_hs() - wait_start));
                    b->thread_exit_sig = false;
                }
                b->key_ready = false;
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->send_poke = true;
            } else {
                /* If configuration is identical but bind is re-requested (e.g. via -id CLI),
                 * we reset the handshake state to trigger a fresh 15-second retry attempt. */
                b->key_ready = false;
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->send_poke = true;
            }
        }
        b->policy_id = profile_id;
        b->profile_id = profile_id;
        b->role_mode = role_mode;
        // Default assignment for is_initiator based on static roles
        if (role_mode == PQC_ROLE_INITIATOR) {
            b->is_initiator = true;
        } else if (role_mode == PQC_ROLE_RESPONDER) {
            b->is_initiator = false;
        } else {
            b->is_initiator = false; // Will be resolved dynamically
        }
        strncpy(b->peer_ip, peer_ip ? peer_ip : "", sizeof(b->peer_ip) - 1);
        b->peer_ip[sizeof(b->peer_ip) - 1] = '\0';
        char clean_local_fg[16] = "";
        if (local_fg) {
            strncpy(clean_local_fg, local_fg, 8);
            clean_local_fg[8] = '\0';
        }
        strncpy(b->local_fingerprint, clean_local_fg, sizeof(b->local_fingerprint) - 1);
        b->local_fingerprint[sizeof(b->local_fingerprint) - 1] = '\0';
        strncpy(b->peer_fingerprint, peer_fg ? peer_fg : "", sizeof(b->peer_fingerprint) - 1);
        b->peer_fingerprint[sizeof(b->peer_fingerprint) - 1] = '\0';
        strncpy(b->wan_ifname, wan_ifname ? wan_ifname : "", sizeof(b->wan_ifname) - 1);
        b->wan_ifname[sizeof(b->wan_ifname) - 1] = '\0';
        b->key_id[0] = '\0';
        b->is_tunnel = true;

        if (b->local_priv) free(b->local_priv);
        if (b->local_pub) free(b->local_pub);
        if (b->peer_pub) free(b->peer_pub);

        b->local_priv = local_priv ? strdup(local_priv) : NULL;
        b->local_pub = local_pub ? strdup(local_pub) : NULL;
        b->peer_pub = deobf_peer;

        const char *role_str = (role_mode == PQC_ROLE_INITIATOR) ? "FORCE_INITIATOR" :
                               (role_mode == PQC_ROLE_RESPONDER) ? "FORCE_RESPONDER" : "DYNAMIC";
        fprintf(stderr, "[PQC-BIND] Profile %d bound in RAM (Local FG: %s, Peer FG: %s, Role Mode: %s, WAN: %s, Peer IP: %s).\n", 
                profile_id, b->local_fingerprint, b->peer_fingerprint, role_str, b->wan_ifname, b->peer_ip);

        int idx = b - g_policy_bindings;
        if (idx >= 0 && idx < MAX_POLICY_BINDINGS) {
            g_policy_key_version[idx]++;
            g_policy_bindings_active[idx] = true;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_find_identity(const char *fingerprint, char **out_priv, char **out_pub) {
    if (!fingerprint) return -1;
    char clean_fg[16] = "";
    strncpy(clean_fg, fingerprint, 8);
    clean_fg[8] = '\0';

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, clean_fg) == 0) {
            if (out_priv) *out_priv = g_identity_registry[i].priv_key;
            if (out_pub) *out_pub = g_identity_registry[i].pub_key;
            pthread_mutex_unlock(&g_key_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    // Fallback: key not in RAM, scan disk to see if it was newly created
    fprintf(stderr, "[PQC-HS] Fingerprint [%s] not found in RAM registry. Reloading from disk...\n", clean_fg);
    sig_pqc_load_keys_from_disk();

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, clean_fg) == 0) {
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
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (g_identity_registry[i].priv_key) {
            free(g_identity_registry[i].priv_key);
            g_identity_registry[i].priv_key = NULL;
        }
        if (g_identity_registry[i].pub_key) {
            free(g_identity_registry[i].pub_key);
            g_identity_registry[i].pub_key = NULL;
        }
    }
    g_registry_count = 0;
    pthread_mutex_unlock(&g_key_mutex);

    DIR *dir = opendir("/dev/shm/.enc_config");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len == 12 && strcmp(entry->d_name + 8, ".key") == 0) {
            char fingerprint[16];
            memset(fingerprint, 0, sizeof(fingerprint));
            strncpy(fingerprint, entry->d_name, 8);

            char priv_path[512];
            char pub_path[512];
            snprintf(priv_path, sizeof(priv_path), "/dev/shm/.enc_config/%s", entry->d_name);
            snprintf(pub_path, sizeof(pub_path), "/etc/.enc_config/%s", entry->d_name);

            FILE *fp_priv = fopen(priv_path, "r");
            if (!fp_priv) continue;
            char raw_file_priv[8192];
            memset(raw_file_priv, 0, sizeof(raw_file_priv));
            if (fgets(raw_file_priv, sizeof(raw_file_priv) - 1, fp_priv) == NULL) {
                fclose(fp_priv);
                continue;
            }
            fclose(fp_priv);
            raw_file_priv[strcspn(raw_file_priv, "\r\n")] = '\0';

            // Verify embedded fingerprint matches
            if (strncmp(raw_file_priv, fingerprint, 8) != 0) {
                fprintf(stderr, "[PQC-LOAD] WARNING: Embedded fingerprint mismatch in private key %s\n", entry->d_name);
                continue;
            }
            const char *obf_priv = raw_file_priv + 8;

            FILE *fp_pub = fopen(pub_path, "r");
            if (!fp_pub) continue;
            char raw_file_pub[8192];
            memset(raw_file_pub, 0, sizeof(raw_file_pub));
            if (fgets(raw_file_pub, sizeof(raw_file_pub) - 1, fp_pub) == NULL) {
                fclose(fp_pub);
                continue;
            }
            fclose(fp_pub);
            raw_file_pub[strcspn(raw_file_pub, "\r\n")] = '\0';

            // Verify embedded fingerprint matches
            if (strncmp(raw_file_pub, fingerprint, 8) != 0) {
                fprintf(stderr, "[PQC-LOAD] WARNING: Embedded fingerprint mismatch in public key %s\n", pub_path);
                continue;
            }
            const char *obf_pub = raw_file_pub + 8;

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

void sig_pqc_prepare_reload(void) {
    pthread_mutex_lock(&g_key_mutex);
    memset(g_policy_bindings_active, 0, sizeof(g_policy_bindings_active));
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_finalize_reload(void) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (!g_policy_bindings_active[i]) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            if (b->local_priv || b->local_pub || b->peer_pub || b->key_ready || b->thread_started) {
                fprintf(stderr, "[PQC-RECONCILE] Profile %d PQC binding is no longer active. Deactivating and clearing keys.\n", b->profile_id);
                if (b->thread_started) {
                    b->thread_exit_sig = true;
                    while (b->thread_started) {
                        pthread_mutex_unlock(&g_key_mutex);
                        usleep(1000);
                        pthread_mutex_lock(&g_key_mutex);
                    }
                    b->thread_exit_sig = false;
                }
                b->key_ready = false;
                if (b->local_priv) { free(b->local_priv); b->local_priv = NULL; }
                if (b->local_pub) { free(b->local_pub); b->local_pub = NULL; }
                if (b->peer_pub) { free(b->peer_pub); b->peer_pub = NULL; }
                memset(b->encrypt_key, 0, PQC_TRAFFIC_KEY_SZ);
                memset(b->decrypt_key, 0, PQC_TRAFFIC_KEY_SZ);
                for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
                    memset(b->keys[slot], 0, PQC_TRAFFIC_KEY_SZ);
                    b->key_slots_valid[slot] = false;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_record_sent(int profile_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            g_policy_bindings[i].last_sent_time = get_time_ms_hs();
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_record_recv(int profile_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            g_policy_bindings[i].last_recv_time = get_time_ms_hs();
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_get_keys(int profile_id, uint8_t keys[3][32], uint8_t key_ids[3], bool key_slots_valid[3]) {
    int idx = -1;
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            idx = i;
            break;
        }
    }
    if (idx == -1) return -1;

    // Lock-free check if the datapath's key version matches the control plane
    if (g_datapath_key_version[idx] == g_policy_key_version[idx]) {
        return 1; // 1 indicates keys are unchanged, skips update
    }

    pthread_mutex_lock(&g_key_mutex);
    memcpy(keys, g_policy_bindings[idx].keys, KEY_SLOT_COUNT * PQC_TRAFFIC_KEY_SZ);
    memcpy(key_ids, g_policy_bindings[idx].key_ids, KEY_SLOT_COUNT);
    memcpy(key_slots_valid, g_policy_bindings[idx].key_slots_valid, KEY_SLOT_COUNT * sizeof(bool));
    g_datapath_key_version[idx] = g_policy_key_version[idx];
    pthread_mutex_unlock(&g_key_mutex);
    return 0; // 0 indicates keys were updated
}

void sig_pqc_promote_responder_key(int profile_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            if (!g_policy_bindings[i].key_slots_valid[KEY_SLOT_NEXT]) {
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }
            // Promote key in control plane as well
            memcpy(g_policy_bindings[i].keys[KEY_SLOT_PREV], g_policy_bindings[i].keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
            g_policy_bindings[i].key_ids[KEY_SLOT_PREV] = g_policy_bindings[i].key_ids[KEY_SLOT_CURRENT];
            g_policy_bindings[i].key_slots_valid[KEY_SLOT_PREV] = g_policy_bindings[i].key_slots_valid[KEY_SLOT_CURRENT];

            memcpy(g_policy_bindings[i].keys[KEY_SLOT_CURRENT], g_policy_bindings[i].keys[KEY_SLOT_NEXT], PQC_TRAFFIC_KEY_SZ);
            g_policy_bindings[i].key_ids[KEY_SLOT_CURRENT] = g_policy_bindings[i].key_ids[KEY_SLOT_NEXT];
            g_policy_bindings[i].key_slots_valid[KEY_SLOT_CURRENT] = true;

            g_policy_bindings[i].key_slots_valid[KEY_SLOT_NEXT] = false;

            // Keep legacy config in sync
            memcpy(g_policy_bindings[i].encrypt_key, g_policy_bindings[i].keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
            memcpy(g_policy_bindings[i].decrypt_key, g_policy_bindings[i].keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);

            fprintf(stderr, "[PQC-HS] Control plane key promoted (NEXT -> CURRENT) for Profile %d!\n", profile_id);
            g_policy_key_version[i]++;
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_discard_prev_key(int profile_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            if (g_policy_bindings[i].key_slots_valid[KEY_SLOT_PREV]) {
                g_policy_bindings[i].key_slots_valid[KEY_SLOT_PREV] = false;
                g_policy_key_version[i]++;
                fprintf(stderr, "[PQC-HS] Discarded PREV key for Profile %d!\n", profile_id);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_trigger_retry(int profile_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->rotation_give_up = false;
            b->rotation_start_time = 0;
            b->key_ready = false;
            b->send_poke = true;
            fprintf(stderr, "[PQC-HS] Manual retry triggered for Profile %d. All retry states reset.\n", profile_id);
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_trigger_retry_with_info(int profile_id, char *out_info, size_t out_max) {
    bool found = false;
    policy_key_binding_t target_binding;
    memset(&target_binding, 0, sizeof(target_binding));

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->rotation_give_up = false;
            b->rotation_start_time = 0;
            b->key_ready = false;
            b->send_poke = true;
            
            target_binding = *b;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (found) {
        snprintf(out_info, out_max,
            "[MANUAL-RETRY] Profile=%d, KeyID=%s, Iface=%s, Peer=%s, Role=%s, Status=RESETTING\n",
            profile_id,
            (strlen(target_binding.key_id) > 0) ? target_binding.key_id : "N/A",
            target_binding.wan_ifname,
            target_binding.peer_ip,
            target_binding.is_initiator ? "Initiator" : "Responder"
        );
        fprintf(stderr, "[PQC-HS] Manual retry triggered for Profile %d. All retry states reset.\n", profile_id);
        return 0;
    } else {
        snprintf(out_info, out_max,
            "[FAILED] Profile ID %d is not active or has no PQC binding configured in RAM.\n",
            profile_id
        );
        return -1;
    }
}
