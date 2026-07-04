#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include "../inc/pqc_l2_handshake.h"
#include "../inc/pqc_logger.h"
#include "packet_crypto.h"
#include <sys/stat.h>
#include <postgresql/libpq-fe.h>
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

static bool g_dispatcher_running = false;

static l2_dispatcher_t g_l2_dispatchers[MAX_L2_DISPATCHERS];
static int g_l2_dispatchers_count = 0;

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
        sig_pqc_write_log(b->policy_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Session key updated.");
    } else {
        sig_pqc_write_log(b->policy_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Secure session established.");
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

    fprintf(stderr, "[PQC-HS] %s Handshake SUCCESS for Policy %d. Promoted new key ID: %d to CURRENT. Key prefix: %02X%02X%02X%02X...\n",
            role, b->policy_id, b->key_ids[KEY_SLOT_CURRENT],
            derived_master[0], derived_master[1], derived_master[2], derived_master[3]);
}

static void initiate_key_rotation(policy_key_binding_t *b, struct pqc_l2_peer *peer, int sockfd, struct sockaddr_in *peeraddr, char *my_priv, char *peer_pub, int profile_id, bool is_l2) {
    fprintf(stderr, "[PQC-HS-%s] Proactively initiating periodic key rotation for Policy %d...\n", is_l2 ? "L2" : "L3", b->policy_id);

    uint8_t pk[2048], sk[4096], ss[128];
    int pk_sz = 0, sk_sz = 0;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-%s] KEM keygen failed during rotation!\n", is_l2 ? "L2" : "L3");
        return;
    }

    uint32_t msg_id = (uint32_t)rand();
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_HELLO;
    msg->session_id = msg_id;
    msg->policy_id = b->policy_id;
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
    if (is_l2) {
        pqc_l2_send_payload_fragmented(peer, msg_id, buffer, payload_tot_sz);
    } else {
        sendto(sockfd, buffer, payload_tot_sz, 0, (const struct sockaddr *)peeraddr, sizeof(struct sockaddr_in));
    }

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
    fprintf(stderr, "[PQC-HS-%s] Key rotation handshake attempt timed out or failed for Policy %d.\n", is_l2 ? "L2" : "L3", b->policy_id);
}

static void pqc_feed_packet_to_policy_l2(policy_key_binding_t *b, const uint8_t *data, int len, const uint8_t *src_mac) {
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
            if (src_mac) {
                memcpy(b->rx_info[b->rx_head].src_mac, src_mac, 6);
            } else {
                memset(b->rx_info[b->rx_head].src_mac, 0, 6);
            }
            b->rx_head = next;
            pthread_cond_signal(&b->rx_cond);
        }
    }
    pthread_mutex_unlock(&b->rx_mutex);
}

void sig_pqc_feed_rx_packet(const uint8_t *payload, int len, const uint8_t *src_mac) {
    if (len < (int)sizeof(struct pqc_hs_msg)) return;
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)payload;
    if (msg->magic != PQC_HS_MAGIC) return;

    uint32_t policy_id = msg->policy_id;
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == (int)policy_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            if (msg->msg_type == PQC_HS_MSG_POKE) {
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->key_ready = false;
                fprintf(stderr, "[PQC-HS] Received POKE message. Resetting handshake retry for Policy %d.\n", policy_id);
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }
            pqc_feed_packet_to_policy_l2(b, payload, len, src_mac);
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

static void* pqc_l2_dispatcher_thread(void *arg) {
    char ifname[64];
    strncpy(ifname, (const char*)arg, 63);
    free(arg);

    fprintf(stderr, "[PQC-L2-DISPATCH] Starting L2 Dispatcher on %s\n", ifname);

    struct pqc_l2_peer peer;
    if (pqc_l2_init_peer(&peer, ifname) < 0) {
        fprintf(stderr, "[PQC-L2-DISPATCH] Failed to initialize L2 peer on %s\n", ifname);
        return NULL;
    }

    while (g_dispatcher_running) {
        uint8_t *rx_payload = NULL;
        uint32_t rx_msg_id = 0;
        int rx_len = pqc_l2_recv_and_process(&peer, &rx_payload, &rx_msg_id);
        if (rx_len > 0 && rx_payload) {
            sig_pqc_feed_rx_packet(rx_payload, rx_len, peer.peer_mac);
            free(rx_payload);
        }
        usleep(10000);
    }

    pqc_l2_cleanup_peer(&peer);
    fprintf(stderr, "[PQC-L2-DISPATCH] Stopped L2 Dispatcher on %s\n", ifname);
    return NULL;
}

static void* pqc_policy_handshake_worker_run(void *arg) {
    policy_key_binding_t *b = (policy_key_binding_t *)arg;
    int policy_id = b->policy_id;
    int profile_id = b->profile_id;

    fprintf(stderr, "[PQC-WORKER] Handshake Worker started for Policy %d (Profile %d)\n", policy_id, profile_id);

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
        fprintf(stderr, "[PQC-WORKER] Policy %d error: local or peer keys not configured.\n", policy_id);
        if (my_priv) free(my_priv);
        if (my_pub) free(my_pub);
        if (peer_pub) free(peer_pub);
        return NULL;
    }

    bool is_bridge_mode = (strlen(wan_ifname) > 0 && 
                          (strlen(peer_ip) == 0 || strcmp(peer_ip, "0.0.0.0") == 0));

    const char *initial_role = (b->role_mode == PQC_ROLE_INITIATOR) ? "INITIATOR" :
                               (b->role_mode == PQC_ROLE_RESPONDER) ? "RESPONDER" : "DYNAMIC (resolving...)";
    fprintf(stderr, "[PQC-WORKER] Policy %d keys loaded. Starting state machine (role: %s, mode: %s)\n",
            policy_id, initial_role, is_bridge_mode ? "L2" : "L3");

    uint8_t pk[2048], sk[4096], ct[2048], ss[128];
    int pk_sz = 0, sk_sz = 0, ct_sz = 0;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    if (is_bridge_mode) {
        struct pqc_l2_peer peer;
        if (pqc_l2_init_peer(&peer, wan_ifname) < 0) {
            fprintf(stderr, "[PQC-WORKER] Policy %d: Failed to init L2 peer on %s\n", policy_id, wan_ifname);
            free(my_priv); free(my_pub); free(peer_pub);
            return NULL;
        }

        while (g_dispatcher_running) {
            if (b->handshake_give_up) {
                usleep(500000);
                continue;
            }
            if (!b->key_ready) {
                if (b->role_mode == PQC_ROLE_DYNAMIC || is_initiator) {
                    fprintf(stderr, "[PQC-WORKER] Policy %d: Initiator peer MAC discovery...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready) {
                        if (pqc_l2_discover_peer_mac(&peer, 5) == 0) {
                            break;
                        }
                        usleep(1000000);
                    }

                    if (!g_dispatcher_running) {
                        break;
                    }

                    if (b->role_mode == PQC_ROLE_DYNAMIC && peer.discovered) {
                        if (memcmp(peer.local_mac, peer.peer_mac, 6) > 0) {
                            is_initiator = true;
                        } else {
                            is_initiator = false;
                        }
                        fprintf(stderr, "[PQC-WORKER-L2] Policy %d: Dynamic role resolved. Local MAC: %02X:%02X:%02X:%02X:%02X:%02X, Peer MAC: %02X:%02X:%02X:%02X:%02X:%02X. Resolved Role: %s\n",
                                policy_id,
                                peer.local_mac[0], peer.local_mac[1], peer.local_mac[2],
                                peer.local_mac[3], peer.local_mac[4], peer.local_mac[5],
                                peer.peer_mac[0], peer.peer_mac[1], peer.peer_mac[2],
                                peer.peer_mac[3], peer.peer_mac[4], peer.peer_mac[5],
                                is_initiator ? "INITIATOR" : "RESPONDER");
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
                        msg->policy_id = policy_id;
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
                        uint32_t msg_id = 10000 + policy_id;
                        int retry_cnt = 0;

                        while (g_dispatcher_running && !b->key_ready) {
                            if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                                fprintf(stderr, "[PQC-HS-L2] Handshake timed out after %d seconds. Giving up on Policy %d.\n",
                                        PQC_HS_GIVEUP_TIMEOUT_MS / 1000, policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Peer connection timeout.");
                                b->handshake_give_up = true;
                                break;
                            }
                            fprintf(stderr, "[PQC-WORKER-L2] Initiator (Policy %d) sending HELLO (try: %d)...\n", policy_id, retry_cnt + 1);
                            pqc_l2_send_payload_fragmented(&peer, msg_id, buffer, payload_tot_sz);

                            uint64_t start_rx = get_time_ms_hs();
                            while (g_dispatcher_running && get_time_ms_hs() - start_rx < 3000 && !b->key_ready) {
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
                    }
                }
                if (!is_initiator && g_dispatcher_running && !b->key_ready) {
                    fprintf(stderr, "[PQC-WORKER-L2] Responder (Policy %d) listening for HELLO...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready) {
                        pthread_mutex_lock(&g_key_mutex);
                        if (b->send_poke) {
                            b->send_poke = false;
                            pthread_mutex_unlock(&g_key_mutex);
                            if (peer.discovered) {
                                struct pqc_hs_msg poke_msg;
                                poke_msg.magic = PQC_HS_MAGIC;
                                poke_msg.msg_type = PQC_HS_MSG_POKE;
                                poke_msg.session_id = 999;
                                poke_msg.policy_id = policy_id;
                                poke_msg.sig_len = 0;
                                poke_msg.data_len = 0;
                                fprintf(stderr, "[PQC-WORKER-L2] Responder (Policy %d) sending POKE to Initiator...\n", policy_id);
                                pqc_l2_send_payload_fragmented(&peer, 999, (uint8_t *)&poke_msg, sizeof(poke_msg));
                            }
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
                                        resp->policy_id = policy_id;
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

                                        memcpy(peer.peer_mac, info.src_mac, 6);
                                        peer.discovered = 1;

                                        pqc_l2_send_payload_fragmented(&peer, msg->session_id, buffer, sizeof(struct pqc_hs_msg) + ct_sz + sig_sz);

                                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                        derive_traffic_key(ss, 32, derived_master);

                                        pthread_mutex_lock(&g_key_mutex);
                                        handle_handshake_success(b, derived_master, "Responder");
                                        pthread_mutex_unlock(&g_key_mutex);

                                        forwarder_pre_diversify_pqc_keys(profile_id);
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
                        fprintf(stderr, "[PQC-HS-L2] Self-healing triggered (Initiator): active TX but no RX. Resetting key for Policy %d.\n", policy_id);
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
                            if (now - b->rotation_start_time > 300000) {
                                fprintf(stderr, "[PQC-HS-L2] Key rotation timed out after 5 minutes. Giving up on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed.");
                                b->rotation_give_up = true;
                            } else {
                                initiate_key_rotation(b, &peer, -1, NULL, my_priv, peer_pub, profile_id, true);
                            }
                        }
                    }
                    usleep(500000);
                } else {
                    uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                    pqc_rx_pkt_info_t info;
                    int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                    if (rx_len > 0) {
                        struct pqc_hs_msg *msg = (struct pqc_hs_msg *)rx_buf;
                        if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                            fprintf(stderr, "[PQC-HS-L2] Responder received HELLO while ONLINE. Peer might have restarted! Re-handshaking for Policy %d...\n", policy_id);

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
                                    resp->policy_id = policy_id;
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

                                    memcpy(peer.peer_mac, info.src_mac, 6);
                                    peer.discovered = 1;

                                    pqc_l2_send_payload_fragmented(&peer, msg->session_id, buffer, sizeof(struct pqc_hs_msg) + ct_sz + sig_sz);

                                    uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                    derive_traffic_key(ss, 32, derived_master);

                                    pthread_mutex_lock(&g_key_mutex);
                                    handle_handshake_success(b, derived_master, "Responder");
                                    pthread_mutex_unlock(&g_key_mutex);

                                    forwarder_pre_diversify_pqc_keys(profile_id);
                                }
                            }
                        } else if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_KEEPALIVE) {
                            fprintf(stderr, "[PQC-HS-L2] Responder received KEEPALIVE for Policy %d. Verifying signature...\n", policy_id);
                            pthread_mutex_lock(&g_key_mutex);
                            size_t raw_pub_sz = 0;
                            uint8_t raw_pub[8192];
                            trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                            pthread_mutex_unlock(&g_key_mutex);

                            if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                                fprintf(stderr, "[PQC-HS-L2] Keepalive verified successfully! Promoting responder key.\n");
                                sig_pqc_promote_responder_key(policy_id);
                            } else {
                                fprintf(stderr, "[PQC-HS-L2] Keepalive signature verification failed!\n");
                            }
                        }
                    }
                    usleep(10000);
                }
            }
        }
        pqc_l2_cleanup_peer(&peer);
    } else {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("[PQC-WORKER] UDP Socket creation failed");
            free(my_priv); free(my_pub); free(peer_pub);
            return NULL;
        }

        struct sockaddr_in peeraddr;
        memset(&peeraddr, 0, sizeof(peeraddr));
        peeraddr.sin_family = AF_INET;
        peeraddr.sin_port = htons(PQC_HS_PORT);
        inet_pton(AF_INET, peer_ip, &peeraddr.sin_addr);

        while (g_dispatcher_running) {
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
                            fprintf(stderr, "[PQC-WORKER-L3] Policy %d: Dynamic role resolved. Local IP: %s (%u), Peer IP: %s (%u). Resolved Role: %s\n",
                                    policy_id, local_ip_str, local_ip_num, peer_ip, peer_ip_num,
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
                    msg->policy_id = policy_id;
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
                    while (g_dispatcher_running && !b->key_ready) {
                        if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                            fprintf(stderr, "[PQC-HS-L3] Handshake timed out after %d seconds. Giving up on Policy %d.\n",
                                    PQC_HS_GIVEUP_TIMEOUT_MS / 1000, policy_id);
                            sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Peer connection timeout.");
                            b->handshake_give_up = true;
                            break;
                        }
                        fprintf(stderr, "[PQC-WORKER-L3] Initiator (Policy %d) sending HELLO (try: %d)...\n", policy_id, retry_cnt + 1);
                        sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz + sig_sz, 0,
                               (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                        uint64_t start_rx = get_time_ms_hs();
                        while (g_dispatcher_running && get_time_ms_hs() - start_rx < 3000 && !b->key_ready) {
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

                                            fprintf(stderr, "[PQC-WORKER-L3] Handshake SUCCESS for Policy %d!\n", policy_id);
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
                    fprintf(stderr, "[PQC-WORKER-L3] Responder (Policy %d) listening for HELLO...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready) {
                        pthread_mutex_lock(&g_key_mutex);
                        if (b->send_poke) {
                            b->send_poke = false;
                            pthread_mutex_unlock(&g_key_mutex);
                            struct pqc_hs_msg poke_msg;
                            poke_msg.magic = PQC_HS_MAGIC;
                            poke_msg.msg_type = PQC_HS_MSG_POKE;
                            poke_msg.session_id = 999;
                            poke_msg.policy_id = policy_id;
                            poke_msg.sig_len = 0;
                            poke_msg.data_len = 0;
                            fprintf(stderr, "[PQC-WORKER-L3] Responder (Policy %d) sending POKE to Initiator...\n", policy_id);
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
                                        resp->policy_id = policy_id;
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
                        fprintf(stderr, "[PQC-HS-L3] Self-healing triggered (Initiator): active TX but no RX. Resetting key for Policy %d.\n", policy_id);
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
                            if (now - b->rotation_start_time > 300000) {
                                fprintf(stderr, "[PQC-HS-L3] Key rotation timed out after 5 minutes. Giving up on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed.");
                                b->rotation_give_up = true;
                            } else {
                                initiate_key_rotation(b, NULL, sockfd, &peeraddr, my_priv, peer_pub, profile_id, false);
                            }
                        }
                    }
                    usleep(500000);
                } else {
                    uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                    pqc_rx_pkt_info_t info;
                    int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                    if (rx_len > 0) {
                        struct pqc_hs_msg *msg = (struct pqc_hs_msg *)rx_buf;
                        if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                            fprintf(stderr, "[PQC-HS-L3] Responder received HELLO while ONLINE. Peer might have restarted! Re-handshaking for Policy %d...\n", policy_id);

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
                                    resp->policy_id = policy_id;
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
                                }
                            }
                        } else if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_KEEPALIVE) {
                            fprintf(stderr, "[PQC-HS-L3] Responder received KEEPALIVE for Policy %d. Verifying signature...\n", policy_id);
                            pthread_mutex_lock(&g_key_mutex);
                            size_t raw_pub_sz = 0;
                            uint8_t raw_pub[8192];
                            trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                            pthread_mutex_unlock(&g_key_mutex);

                            if (trf_dsa_verify_payload(raw_pub, raw_pub_sz, msg->payload, msg->data_len, msg->payload + msg->data_len, msg->sig_len) == TRF_PQC_OK) {
                                fprintf(stderr, "[PQC-HS-L3] Keepalive verified successfully! Promoting responder key.\n");
                                sig_pqc_promote_responder_key(policy_id);
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
    }
    free(my_priv);
    free(my_pub);
    free(peer_pub);
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

    bool is_bridge_mode = (wan_ifname && strlen(wan_ifname) > 0 && 
                          (!peer_ip || strlen(peer_ip) == 0 || strcmp(peer_ip, "0.0.0.0") == 0));
    if (is_bridge_mode && wan_ifname) {
        pthread_mutex_lock(&g_key_mutex);
        bool l2_running = false;
        for (int i = 0; i < g_l2_dispatchers_count; i++) {
            if (strcmp(g_l2_dispatchers[i].ifname, wan_ifname) == 0) {
                l2_running = true;
                break;
            }
        }
        if (!l2_running && g_l2_dispatchers_count < MAX_L2_DISPATCHERS) {
            char *ifname_copy = strdup(wan_ifname);
            pthread_t l2_tid;
            if (pthread_create(&l2_tid, NULL, pqc_l2_dispatcher_thread, ifname_copy) == 0) {
                pthread_detach(l2_tid);
                strncpy(g_l2_dispatchers[g_l2_dispatchers_count].ifname, wan_ifname, 63);
                g_l2_dispatchers[g_l2_dispatchers_count].thread = l2_tid;
                g_l2_dispatchers[g_l2_dispatchers_count].running = true;
                g_l2_dispatchers_count++;
            } else {
                free(ifname_copy);
                fprintf(stderr, "[PQC-HS] ERROR starting L2 dispatcher on %s\n", wan_ifname);
            }
        }
        pthread_mutex_unlock(&g_key_mutex);
    }

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
                    fprintf(stderr, "[PQC-HS] Spawned Handshake Worker for Policy %d (Profile %d)\n", 
                            g_policy_bindings[i].policy_id, profile_id);
                } else {
                    g_policy_bindings[i].thread_started = false;
                    fprintf(stderr, "[PQC-HS] ERROR: Failed to spawn Handshake Worker for Policy %d\n", 
                            g_policy_bindings[i].policy_id);
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
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
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

char* sig_pqc_deobfuscate_peer_pub(const char *obf_pub_str, const char *peer_fingerprint) {
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

void sig_pqc_bind_policy(int policy_id, int profile_id, int role_mode,
                         const char *peer_ip, const char *local_fg,
                         const char *peer_fg, const char *wan_ifname,
                         const char *key_id,
                         const char *local_priv, const char *local_pub,
                         const char *peer_pub) {
    char *deobf_peer = peer_pub ? strdup(peer_pub) : NULL;

    pthread_mutex_lock(&g_key_mutex);
    policy_key_binding_t *b = NULL;
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            b = &g_policy_bindings[i];
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
        for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
            memset(b->keys[slot], 0, PQC_TRAFFIC_KEY_SZ);
            b->key_ids[slot] = 0;
            b->key_slots_valid[slot] = false;
        }
    }
    if (b) {
        b->policy_id = policy_id;
        b->profile_id = profile_id;
        b->role_mode = role_mode;
        // Default assignment for is_initiator based on static modes
        if (role_mode == PQC_ROLE_INITIATOR) {
            b->is_initiator = true;
        } else if (role_mode == PQC_ROLE_RESPONDER) {
            b->is_initiator = false;
        } else {
            b->is_initiator = false; // Will be resolved dynamically
        }
        strncpy(b->peer_ip, peer_ip ? peer_ip : "", sizeof(b->peer_ip) - 1);
        b->peer_ip[sizeof(b->peer_ip) - 1] = '\0';
        strncpy(b->local_fingerprint, local_fg ? local_fg : "", sizeof(b->local_fingerprint) - 1);
        b->local_fingerprint[sizeof(b->local_fingerprint) - 1] = '\0';
        strncpy(b->peer_fingerprint, peer_fg ? peer_fg : "", sizeof(b->peer_fingerprint) - 1);
        b->peer_fingerprint[sizeof(b->peer_fingerprint) - 1] = '\0';
        strncpy(b->wan_ifname, wan_ifname ? wan_ifname : "", sizeof(b->wan_ifname) - 1);
        b->wan_ifname[sizeof(b->wan_ifname) - 1] = '\0';
        strncpy(b->key_id, key_id ? key_id : "", sizeof(b->key_id) - 1);
        b->key_id[sizeof(b->key_id) - 1] = '\0';

        if (b->local_priv) free(b->local_priv);
        if (b->local_pub) free(b->local_pub);
        if (b->peer_pub) free(b->peer_pub);

        b->local_priv = local_priv ? strdup(local_priv) : NULL;
        b->local_pub = local_pub ? strdup(local_pub) : NULL;
        b->peer_pub = deobf_peer;

        const char *role_str = (role_mode == PQC_ROLE_INITIATOR) ? "FORCE_INITIATOR" :
                               (role_mode == PQC_ROLE_RESPONDER) ? "FORCE_RESPONDER" : "DYNAMIC";
        fprintf(stderr, "[PQC-BIND] Policy %d bound in RAM (Local FG: %s, Peer FG: %s, Role Mode: %s, WAN: %s, Peer IP: %s).\n", 
                policy_id, b->local_fingerprint, b->peer_fingerprint, role_str, b->wan_ifname, b->peer_ip);

        int idx = b - g_policy_bindings;
        if (idx >= 0 && idx < MAX_POLICY_BINDINGS) {
            g_policy_key_version[idx]++;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
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

void sig_pqc_record_sent(int policy_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            g_policy_bindings[i].last_sent_time = get_time_ms_hs();
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_record_recv(int policy_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            g_policy_bindings[i].last_recv_time = get_time_ms_hs();
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_get_keys(int policy_id, uint8_t keys[3][32], uint8_t key_ids[3], bool key_slots_valid[3]) {
    int idx = -1;
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
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

void sig_pqc_promote_responder_key(int policy_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
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

            fprintf(stderr, "[PQC-HS] Control plane key promoted (NEXT -> CURRENT) for Policy %d!\n", policy_id);
            g_policy_key_version[i]++;
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_discard_prev_key(int policy_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            if (g_policy_bindings[i].key_slots_valid[KEY_SLOT_PREV]) {
                g_policy_bindings[i].key_slots_valid[KEY_SLOT_PREV] = false;
                g_policy_key_version[i]++;
                fprintf(stderr, "[PQC-HS] Discarded PREV key for Policy %d!\n", policy_id);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_trigger_retry(int policy_id) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->rotation_give_up = false;
            b->rotation_start_time = 0;
            b->key_ready = false;
            b->send_poke = true;
            fprintf(stderr, "[PQC-HS] Manual retry triggered for Policy %d. All retry states reset.\n", policy_id);
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_trigger_retry_with_info(int policy_id, char *out_info, size_t out_max) {
    bool found = false;
    policy_key_binding_t target_binding;
    memset(&target_binding, 0, sizeof(target_binding));

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
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
            "[MANUAL-RETRY] Policy=%d, Profile=%d, KeyID=%s, Iface=%s, Peer=%s, Role=%s, Status=RESETTING\n",
            policy_id,
            target_binding.profile_id,
            (strlen(target_binding.key_id) > 0) ? target_binding.key_id : "N/A",
            target_binding.wan_ifname,
            target_binding.peer_ip,
            target_binding.is_initiator ? "Initiator" : "Responder"
        );
        fprintf(stderr, "[PQC-HS] Manual retry triggered for Policy %d. All retry states reset.\n", policy_id);
        return 0;
    } else {
        snprintf(out_info, out_max,
            "[FAILED] Policy ID %d is not active or has no PQC binding configured in RAM.\n",
            policy_id
        );
        return -1;
    }
}

void sig_pqc_load_and_bind_policy(void *conn_ptr, const void *cfg_ptr, int profile_idx, int db_policy_id, int profile_id) {
    PGconn *conn = (PGconn *)conn_ptr;
    const struct app_config *cfg = (const struct app_config *)cfg_ptr;
    (void)profile_idx;
    (void)cfg;

    char peer_ip[64] = "0.0.0.0";
    char wan_ifname_buf[64] = "";
    const char *wan_ifname = "";

    char policy_id_str[32];
    snprintf(policy_id_str, sizeof(policy_id_str), "%d", db_policy_id);
    const char *pqc_params[1] = { policy_id_str };

    // Query to get the tunnel parameters from pqc_exchange_tunnels
    PGresult *tunnel_res = PQexecParams(conn,
        "SELECT t.tunnel_name, t.client_tunnel_ip::text, t.peer_tunnel_ip::text "
        "FROM pqc_exchange_tunnels t "
        "JOIN profile_tunnel_ref r ON t.id = r.tunnel_id "
        "JOIN ne_policies p ON r.profile_id = p.profile_id "
        "WHERE p.id = $1",
        1, NULL, pqc_params, NULL, NULL, 0);

    if (PQresultStatus(tunnel_res) == PGRES_TUPLES_OK && PQntuples(tunnel_res) > 0) {
        const char *t_name = PQgetvalue(tunnel_res, 0, 0);
        const char *client_ip = PQgetvalue(tunnel_res, 0, 1);
        const char *peer_ip_db = PQgetvalue(tunnel_res, 0, 2);

        if (t_name) {
            strncpy(wan_ifname_buf, t_name, sizeof(wan_ifname_buf) - 1);
            wan_ifname = wan_ifname_buf;

            // Resolve local IP on the tunnel interface
            char local_ip[64] = "0.0.0.0";
            int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (temp_sock >= 0) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, t_name, IFNAMSIZ - 1);
                ifr.ifr_addr.sa_family = AF_INET;
                if (ioctl(temp_sock, SIOCGIFADDR, &ifr) == 0) {
                    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
                    strncpy(local_ip, inet_ntoa(ipaddr->sin_addr), sizeof(local_ip) - 1);
                }
                close(temp_sock);
            }

            // Compare local IP with client_tunnel_ip and peer_tunnel_ip
            if (client_ip && peer_ip_db) {
                if (strcmp(local_ip, client_ip) == 0) {
                    strncpy(peer_ip, peer_ip_db, sizeof(peer_ip) - 1);
                } else if (strcmp(local_ip, peer_ip_db) == 0) {
                    strncpy(peer_ip, client_ip, sizeof(peer_ip) - 1);
                } else {
                    strncpy(peer_ip, peer_ip_db, sizeof(peer_ip) - 1);
                }
            }
            fprintf(stderr, "[DB-PQC] Tunnel resolved: Name=%s, LocalIP=%s, PeerIP=%s\n",
                    t_name, local_ip, peer_ip);
        }
    } else {
        fprintf(stderr, "[DB-PQC] Warning: No tunnel configuration found for policy %d\n", db_policy_id);
    }
    PQclear(tunnel_res);

    PGresult *peer_res = PQexecParams(conn,
        "SELECT k.local, k.remote, k.key_id "
        "FROM pqc_keys k "
        "JOIN policy_pqc_ref r ON k.key_id = r.key_id "
        "WHERE r.policy_id = $1",
        1, NULL, pqc_params, NULL, NULL, 0);

    if (PQresultStatus(peer_res) == PGRES_TUPLES_OK && PQntuples(peer_res) > 0) {
        const char *local_fg = PQgetvalue(peer_res, 0, 0);
        const char *peer_pub_path = PQgetvalue(peer_res, 0, 1);
        const char *key_id = PQgetvalue(peer_res, 0, 2);

        char resolved_peer_pub_path[512] = "";
        if (peer_pub_path && strlen(peer_pub_path) > 0) {
            if (peer_pub_path[0] == '/') {
                strncpy(resolved_peer_pub_path, peer_pub_path, sizeof(resolved_peer_pub_path) - 1);
            } else {
                snprintf(resolved_peer_pub_path, sizeof(resolved_peer_pub_path), "/etc/.dec_config/%s", peer_pub_path);
            }
        }

        char peer_fg_buf[16] = "";
        char *deobf_pub = NULL;
        bool valid = true;

        if (strlen(resolved_peer_pub_path) == 0) {
            fprintf(stderr, "[DB-PQC] ERROR: Policy %d is missing peer_pub key file path in DB!\n", db_policy_id);
            valid = false;
        } else {
            FILE *fp_pub = fopen(resolved_peer_pub_path, "r");
            if (!fp_pub) {
                fprintf(stderr, "[DB-PQC] ERROR: Policy %d peer_pub key file [%s] could not be opened!\n", db_policy_id, resolved_peer_pub_path);
                valid = false;
            } else {
                char file_content[8192];
                memset(file_content, 0, sizeof(file_content));
                if (fgets(file_content, sizeof(file_content) - 1, fp_pub) == NULL) {
                    fprintf(stderr, "[DB-PQC] ERROR: Policy %d peer_pub key file [%s] is empty!\n", db_policy_id, resolved_peer_pub_path);
                    valid = false;
                } else {
                    file_content[strcspn(file_content, "\r\n")] = '\0';
                    if (strlen(file_content) < 8) {
                        fprintf(stderr, "[DB-PQC] ERROR: Policy %d peer_pub key file [%s] has invalid format (too short)!\n", db_policy_id, resolved_peer_pub_path);
                        valid = false;
                    } else {
                        strncpy(peer_fg_buf, file_content, 8);
                        peer_fg_buf[8] = '\0';
                        const char *obf_pub = file_content + 8;
                        deobf_pub = sig_pqc_deobfuscate_peer_pub(obf_pub, peer_fg_buf);
                        if (!deobf_pub) {
                            fprintf(stderr, "[DB-PQC] ERROR: Policy %d peer_pub key file [%s] deobfuscation failed!\n", db_policy_id, resolved_peer_pub_path);
                            valid = false;
                        }
                    }
                }
                fclose(fp_pub);
            }
        }

        int role_mode = PQC_USE_DYNAMIC_ROLE ? PQC_ROLE_DYNAMIC : PQC_ROLE_RESPONDER;

        char *found_priv = NULL;
        char *found_pub = NULL;
        if (valid) {
            sig_pqc_find_identity(local_fg, &found_priv, &found_pub);
            if (!found_priv || !found_pub) {
                fprintf(stderr, "[DB-PQC] ERROR: Local keys for fingerprint [%s] (Policy %d) are not loaded in memory registry! (Please run key generator command first)\n", local_fg, db_policy_id);
                valid = false;
            }
        }

        if (valid) {
            sig_pqc_bind_policy(db_policy_id, profile_id, role_mode, peer_ip, local_fg, peer_fg_buf, wan_ifname, key_id, found_priv, found_pub, deobf_pub);
        } else {
            fprintf(stderr, "[DB-PQC] ERROR: Policy %d PQC config is invalid or keys are missing. PQC Handshake will NOT start.\n", db_policy_id);
            sig_pqc_write_log(db_policy_id, key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Security configuration error.");
        }
        if (deobf_pub) free(deobf_pub);
    } else {
        fprintf(stderr, "[DB-PQC] ERROR: No policy identity configuration found in pqc_identities for PQC policy %d. PQC Handshake will NOT start.\n", db_policy_id);
        sig_pqc_write_log(db_policy_id, "", PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Security configuration error.");
    }
    PQclear(peer_res);
}
