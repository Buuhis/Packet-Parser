#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include "../inc/pqc_logger.h"
#include "../inc/pqc_vault.h"
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
#include <sys/random.h>
#include <net/if.h>

#define PQC_RX_PKT_MAX     10000
#define KEY_ROTATION_INTERVAL_MS 3000000
#define PQC_HS_GIVEUP_TIMEOUT_MS 15000

/* TEST ONLY: allow the two peers to use different local profile IDs.
 * Set this back to 0 after the profile-mismatch test. */
#define PQC_TEST_ALLOW_PROFILE_MISMATCH 1

extern void sig_pqc_on_key_ready(int profile_id, const uint8_t *key_bytes,
                                 uint64_t config_generation);

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

static bool pqc_hs_profile_matches(uint32_t wire_profile_id,
                                   int local_profile_id) {
#if PQC_TEST_ALLOW_PROFILE_MISMATCH
    (void)wire_profile_id;
    (void)local_profile_id;
    return true;
#else
    return wire_profile_id == (uint32_t)local_profile_id;
#endif
}

/* g_key_mutex must be held. Exact profile matches always win. In test mode,
 * mismatched IDs may fall back only when exactly one active PQC binding exists;
 * multiple bindings would make routing the packet ambiguous. */
static int pqc_hs_find_rx_binding_locked(uint32_t wire_profile_id) {
    int fallback = -1;

    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings_active[i] &&
            g_policy_bindings[i].profile_id == (int)wire_profile_id)
            return i;
    }

#if PQC_TEST_ALLOW_PROFILE_MISMATCH
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (!g_policy_bindings_active[i]) continue;
        if (fallback >= 0) return -1;
        fallback = i;
    }
#endif

    return fallback;
}

static int pqc_generate_session_id(uint32_t *session_id) {
    uint32_t value = 0;

    if (!session_id) return -1;

    do {
        size_t filled = 0;
        while (filled < sizeof(value)) {
            ssize_t n = getrandom((uint8_t *)&value + filled,
                                  sizeof(value) - filled, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (n == 0) {
                errno = EIO;
                return -1;
            }
            filled += (size_t)n;
        }
    } while (value == 0);

    *session_id = value;
    return 0;
}

static int pqc_hs_validate_message(const uint8_t *buf, int rx_len,
                                   const struct pqc_hs_msg **msg_out) {
    const struct pqc_hs_msg *msg;
    size_t total_len;

    if (!buf || rx_len < (int)sizeof(struct pqc_hs_msg)) return -1;

    msg = (const struct pqc_hs_msg *)buf;
    total_len = sizeof(*msg) + (size_t)msg->data_len + (size_t)msg->sig_len;
    if (total_len > PQC_HS_MSG_MAX_SZ || total_len != (size_t)rx_len) return -1;

    if (msg_out) *msg_out = msg;
    return 0;
}

static int pqc_hs_transcript_hash(const struct pqc_hs_msg *msg,
                                  uint8_t digest[32]) {
    uint8_t transcript[PQC_HS_MSG_MAX_SZ];
    struct pqc_hs_msg *normalized = (struct pqc_hs_msg *)transcript;
    size_t transcript_len;

    if (!msg || !digest) return -1;
    transcript_len = sizeof(*msg) + (size_t)msg->data_len;
    if (transcript_len > sizeof(transcript)) return -1;

    memcpy(transcript, msg, transcript_len);
    normalized->sig_len = 0;
    return trf_calculate_digest(DIGEST_TYPE_SHA256, transcript,
                                (int)transcript_len, digest) == TRF_PQC_OK ? 0 : -1;
}

static int pqc_hs_sign_message(const uint8_t *priv_key, size_t priv_key_len,
                               const struct pqc_hs_msg *msg,
                               uint8_t *signature, int *signature_len) {
    uint8_t digest[32];

    if (pqc_hs_transcript_hash(msg, digest) != 0) return -1;
    return trf_dsa_sign_payload(priv_key, (int)priv_key_len,
                                digest, sizeof(digest),
                                signature, signature_len);
}

static int pqc_hs_verify_message(const uint8_t *pub_key, size_t pub_key_len,
                                 const struct pqc_hs_msg *msg) {
    uint8_t digest[32];

    if (pqc_hs_transcript_hash(msg, digest) != 0) return -1;
    return trf_dsa_verify_payload(pub_key, (int)pub_key_len,
                                  digest, sizeof(digest),
                                  msg->payload + msg->data_len,
                                  msg->sig_len);
}

static void pqc_hs_clear_cache_locked(policy_key_binding_t *b) {
    if (!b) return;

    for (int i = 0; i < PQC_HS_CACHE_SLOTS; i++) {
        free(b->hs_cache[i].response);
        memset(&b->hs_cache[i], 0, sizeof(b->hs_cache[i]));
    }
    b->hs_cache_next = 0;
}

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

}

static int pqc_hs_send_cached_response(policy_key_binding_t *b, int cache_slot,
                                       uint32_t session_id, const uint8_t hello_hash[32],
                                       int sockfd, const struct sockaddr_in *peeraddr,
                                       bool replay) {
    uint8_t *response = NULL;
    uint8_t master_key[PQC_TRAFFIC_KEY_SZ];
    int response_len = 0;
    bool already_promoted = false;
    bool promote_now = false;
    uint64_t callback_generation = 0;
    ssize_t sent;

    pthread_mutex_lock(&g_key_mutex);
    if (cache_slot < 0 || cache_slot >= PQC_HS_CACHE_SLOTS ||
        !b->hs_cache[cache_slot].valid ||
        b->hs_cache[cache_slot].session_id != session_id ||
        memcmp(b->hs_cache[cache_slot].hello_hash, hello_hash, 32) != 0 ||
        !b->hs_cache[cache_slot].response ||
        b->hs_cache[cache_slot].response_len <= 0) {
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }

    response_len = b->hs_cache[cache_slot].response_len;
    response = malloc((size_t)response_len);
    if (response) {
        memcpy(response, b->hs_cache[cache_slot].response, (size_t)response_len);
        memcpy(master_key, b->hs_cache[cache_slot].master_key, sizeof(master_key));
        already_promoted = b->hs_cache[cache_slot].key_promoted;
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (!response) return -1;

    sent = sendto(sockfd, response, (size_t)response_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    free(response);
    if (sent != response_len) {
        fprintf(stderr,
                "[PQC-HS-L3] Failed to send RESP for Profile %d, session %u: %s\n",
                b->profile_id, session_id,
                sent < 0 ? strerror(errno) : "short UDP send");
        return -1;
    }

    if (!already_promoted) {
        pthread_mutex_lock(&g_key_mutex);
        if (b->hs_cache[cache_slot].valid &&
            b->hs_cache[cache_slot].session_id == session_id &&
            memcmp(b->hs_cache[cache_slot].hello_hash, hello_hash, 32) == 0 &&
            !b->hs_cache[cache_slot].key_promoted) {
            b->hs_cache[cache_slot].key_promoted = true;
            handle_handshake_success(b, master_key, "Responder");
            memset(b->hs_cache[cache_slot].master_key, 0,
                   sizeof(b->hs_cache[cache_slot].master_key));
            callback_generation = b->config_generation;
            promote_now = true;
        }
        pthread_mutex_unlock(&g_key_mutex);
    }

    if (promote_now) {
        sig_pqc_on_key_ready(b->profile_id, master_key,
                             callback_generation);
        forwarder_pre_diversify_pqc_keys(b->profile_id);
    }

    fprintf(stderr,
            "[PQC-HS-L3] Responder %s RESP for Profile %d, session %u%s.\n",
            replay ? "replayed cached" : "sent new",
            b->profile_id, session_id,
            already_promoted ? " (key unchanged)" : "");
    return 0;
}

static int pqc_hs_handle_responder_hello(policy_key_binding_t *b,
                                         int sockfd,
                                         const struct sockaddr_in *peeraddr,
                                         const uint8_t *rx_buf, int rx_len,
                                         char **my_priv, char **peer_pub) {
    const struct pqc_hs_msg *msg;
    uint8_t hello_hash[32];
    uint8_t raw_pub[8192];
    uint8_t raw_priv[8192];
    uint8_t ct[2048];
    uint8_t ss[128];
    uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
    uint8_t response_buf[PQC_HS_MSG_MAX_SZ];
    size_t raw_pub_sz = 0;
    size_t raw_priv_sz = 0;
    int ct_sz = 0;
    int sig_sz = 0;
    int response_len;
    int cached_slot = -1;
    bool session_conflict = false;
    char *new_my_priv = NULL;
    char *new_peer_pub = NULL;

    if (pqc_hs_validate_message(rx_buf, rx_len, &msg) != 0 ||
        msg->magic != PQC_HS_MAGIC || msg->msg_type != PQC_HS_MSG_HELLO ||
        !pqc_hs_profile_matches(msg->profile_id, b->profile_id) ||
        msg->session_id == 0) {
        fprintf(stderr, "[PQC-HS-L3] Rejected malformed/mismatched HELLO for Profile %d.\n",
                b->profile_id);
        return -1;
    }

    if (trf_calculate_digest(DIGEST_TYPE_SHA256, rx_buf, rx_len, hello_hash) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] Failed to fingerprint HELLO for Profile %d.\n",
                b->profile_id);
        return -1;
    }

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < PQC_HS_CACHE_SLOTS; i++) {
        if (!b->hs_cache[i].valid || b->hs_cache[i].session_id != msg->session_id) continue;
        if (memcmp(b->hs_cache[i].hello_hash, hello_hash, sizeof(hello_hash)) == 0) {
            cached_slot = i;
        } else {
            session_conflict = true;
        }
        break;
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (session_conflict) {
        fprintf(stderr,
                "[PQC-HS-L3] Rejected HELLO reusing session %u with different content for Profile %d.\n",
                msg->session_id, b->profile_id);
        return -1;
    }
    if (cached_slot >= 0) {
        return pqc_hs_send_cached_response(b, cached_slot, msg->session_id,
                                           hello_hash, sockfd, peeraddr, true);
    }

    pthread_mutex_lock(&g_key_mutex);
    if (b->local_priv && b->local_priv[0] != '\0') new_my_priv = strdup(b->local_priv);
    if (b->peer_pub && b->peer_pub[0] != '\0') new_peer_pub = strdup(b->peer_pub);
    pthread_mutex_unlock(&g_key_mutex);

    if (!new_my_priv || !new_peer_pub) {
        free(new_my_priv);
        free(new_peer_pub);
        fprintf(stderr, "[PQC-HS-L3] Missing responder authentication keys for Profile %d.\n",
                b->profile_id);
        return -1;
    }
    free(*my_priv);
    free(*peer_pub);
    *my_priv = new_my_priv;
    *peer_pub = new_peer_pub;

    trf_base64_decode(*peer_pub, raw_pub, &raw_pub_sz);
    if (pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK) {
        fprintf(stderr,
                "[PQC-HS-L3] HELLO signature verification failed for Profile %d, session %u.\n",
                b->profile_id, msg->session_id);
        sig_pqc_write_log(b->profile_id, b->key_id, PQC_LOG_LEVEL_ERROR,
                          PQC_LOG_STATUS_FAILED,
                          "Handshake signature verification failed. Mismatched authentication keys.");
        return -1;
    }

    if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] KEM encapsulation failed for Profile %d, session %u.\n",
                b->profile_id, msg->session_id);
        return -1;
    }

    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)response_buf;
    resp->magic = PQC_HS_MAGIC;
    resp->msg_type = PQC_HS_MSG_RESP;
    resp->session_id = msg->session_id;
    resp->profile_id = (uint32_t)b->profile_id;
    resp->data_len = (uint16_t)ct_sz;
    memcpy(resp->payload, ct, (size_t)ct_sz);

    trf_base64_decode(*my_priv, raw_priv, &raw_priv_sz);
    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, resp,
                            resp->payload + ct_sz, &sig_sz) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] Failed to sign RESP for Profile %d, session %u.\n",
                b->profile_id, msg->session_id);
        return -1;
    }
    resp->sig_len = (uint16_t)sig_sz;
    response_len = (int)sizeof(*resp) + ct_sz + sig_sz;
    if (response_len > PQC_HS_MSG_MAX_SZ) return -1;

    derive_traffic_key(ss, 32, derived_master);

    uint8_t *response_copy = malloc((size_t)response_len);
    if (!response_copy) return -1;
    memcpy(response_copy, response_buf, (size_t)response_len);

    pthread_mutex_lock(&g_key_mutex);
    cached_slot = b->hs_cache_next;
    b->hs_cache_next = (b->hs_cache_next + 1) % PQC_HS_CACHE_SLOTS;
    free(b->hs_cache[cached_slot].response);
    memset(&b->hs_cache[cached_slot], 0, sizeof(b->hs_cache[cached_slot]));
    b->hs_cache[cached_slot].response = response_copy;
    b->hs_cache[cached_slot].response_len = response_len;
    b->hs_cache[cached_slot].session_id = msg->session_id;
    memcpy(b->hs_cache[cached_slot].hello_hash, hello_hash, sizeof(hello_hash));
    memcpy(b->hs_cache[cached_slot].master_key, derived_master, sizeof(derived_master));
    b->hs_cache[cached_slot].valid = true;
    pthread_mutex_unlock(&g_key_mutex);

    return pqc_hs_send_cached_response(b, cached_slot, msg->session_id,
                                       hello_hash, sockfd, peeraddr, false);
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

    uint32_t msg_id;
    if (pqc_generate_session_id(&msg_id) != 0) {
        fprintf(stderr, "[PQC-HS-L3] Cannot generate a secure rotation session ID: %s\n",
                strerror(errno));
        return;
    }
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
    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                            msg->payload + pk_sz, &sig_sz) != TRF_PQC_OK) {
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr, "[PQC-HS-L3] Failed to sign rotation HELLO for Profile %d.\n",
                b->profile_id);
        return;
    }
    msg->sig_len = (uint16_t)sig_sz;
    pthread_mutex_unlock(&g_key_mutex);

    int payload_tot_sz = sizeof(struct pqc_hs_msg) + pk_sz + sig_sz;
    uint64_t rotation_started = get_time_ms_hs();
    int retry_cnt = 0;

    while (g_dispatcher_running && !b->thread_exit_sig &&
           get_time_ms_hs() - rotation_started < PQC_HS_GIVEUP_TIMEOUT_MS) {
        ssize_t sent = sendto(sockfd, buffer, payload_tot_sz, 0,
                              (const struct sockaddr *)peeraddr,
                              sizeof(struct sockaddr_in));
        fprintf(stderr,
                "[PQC-HS-L3] Rotation HELLO Profile %d, session %u, try %d%s.\n",
                profile_id, msg_id, ++retry_cnt,
                sent == payload_tot_sz ? " sent" : " send failed");

        uint64_t start_rx = get_time_ms_hs();
        while (g_dispatcher_running && !b->thread_exit_sig &&
               get_time_ms_hs() - start_rx < 3000) {
            uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
            pqc_rx_pkt_info_t info;
            int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
            if (rx_len > 0) {
                const struct pqc_hs_msg *resp = NULL;
                if (pqc_hs_validate_message(rx_buf, rx_len, &resp) == 0 &&
                    resp->magic == PQC_HS_MAGIC &&
                    resp->msg_type == PQC_HS_MSG_RESP &&
                    resp->session_id == msg_id &&
                    pqc_hs_profile_matches(resp->profile_id, profile_id)) {
                    pthread_mutex_lock(&g_key_mutex);
                    size_t raw_pub_sz = 0;
                    uint8_t raw_pub[8192];
                    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                    pthread_mutex_unlock(&g_key_mutex);

                    if (pqc_hs_verify_message(raw_pub, raw_pub_sz, resp) == TRF_PQC_OK &&
                        trf_kem_decapsulate(sk, sk_sz, resp->payload,
                                            resp->data_len, ss) == TRF_PQC_OK) {
                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                        derive_traffic_key(ss, 32, derived_master);

                        uint64_t callback_generation;

                        pthread_mutex_lock(&g_key_mutex);
                        handle_handshake_success(b, derived_master, "Initiator");
                        callback_generation = b->config_generation;
                        pthread_mutex_unlock(&g_key_mutex);

                        sig_pqc_on_key_ready(profile_id, derived_master,
                                             callback_generation);
                        forwarder_pre_diversify_pqc_keys(profile_id);
                        return;
                    }
                }
            }
            usleep(10000);
        }
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
    int binding_idx = pqc_hs_find_rx_binding_locked(profile_id);
    if (binding_idx >= 0) {
        policy_key_binding_t *b = &g_policy_bindings[binding_idx];
#if PQC_TEST_ALLOW_PROFILE_MISMATCH
        if (b->profile_id != (int)profile_id) {
            fprintf(stderr,
                    "[PQC-HS-TEST] Accepting wire profile %u on local profile %d.\n",
                    profile_id, b->profile_id);
        }
#endif
        if (msg->msg_type == PQC_HS_MSG_POKE) {
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->rotation_give_up = false;
            b->rotation_start_time = 0;
            b->key_ready = false;
            pthread_mutex_lock(&b->rx_mutex);
            for (int q = 0; q < PQC_RX_QUEUE_SIZE; q++) {
                if (b->rx_queue[q]) { free(b->rx_queue[q]); b->rx_queue[q] = NULL; }
                b->rx_len[q] = 0;
            }
            b->rx_head = 0; b->rx_tail = 0;
            pthread_mutex_unlock(&b->rx_mutex);
            fprintf(stderr, "[PQC-HS] Received POKE message. Resetting handshake retry and flushing rx queue for Profile %d.\n", profile_id);
            pthread_mutex_unlock(&g_key_mutex);
            return;
        } else if (msg->msg_type == PQC_HS_MSG_HELLO) {
            if (b->handshake_give_up) {
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->key_ready = false;
                pthread_mutex_lock(&b->rx_mutex);
                for (int q = 0; q < PQC_RX_QUEUE_SIZE; q++) {
                    if (b->rx_queue[q]) { free(b->rx_queue[q]); b->rx_queue[q] = NULL; }
                    b->rx_len[q] = 0;
                }
                b->rx_head = 0; b->rx_tail = 0;
                pthread_mutex_unlock(&b->rx_mutex);
                fprintf(stderr, "[PQC-HS] Received HELLO message while asleep. Waking up Responder and flushing rx queue for Profile %d.\n", profile_id);
            }
        }
        pqc_feed_packet_to_binding_queue(b, payload, len);
        pthread_mutex_unlock(&g_key_mutex);
        return;
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
    char local_ip[64];
    strncpy(local_ip, b->local_ip, sizeof(local_ip) - 1);
    local_ip[sizeof(local_ip) - 1] = '\0';
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

    uint8_t pk[2048], sk[4096], ss[128];
    int pk_sz = 0, sk_sz = 0;
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

    if (wan_ifname[0] == '\0' ||
        setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, wan_ifname,
                   strlen(wan_ifname) + 1) < 0) {
        fprintf(stderr, "[PQC-WORKER] Cannot bind socket to tunnel %s: %s\n",
                wan_ifname[0] ? wan_ifname : "<empty>", strerror(errno));
        close(sockfd);
        free(my_priv); free(my_pub); free(peer_pub);
        pthread_mutex_lock(&g_key_mutex);
        b->thread_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return NULL;
    }

    {
        struct sockaddr_in localaddr;

        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = 0;
        if (inet_pton(AF_INET, local_ip, &localaddr.sin_addr) != 1 ||
            bind(sockfd, (const struct sockaddr *)&localaddr,
                 sizeof(localaddr)) < 0) {
            fprintf(stderr, "[PQC-WORKER] Cannot bind %s on %s: %s\n",
                    local_ip, wan_ifname, strerror(errno));
            close(sockfd);
            free(my_priv); free(my_pub); free(peer_pub);
            pthread_mutex_lock(&g_key_mutex);
            b->thread_started = false;
            pthread_mutex_unlock(&g_key_mutex);
            return NULL;
        }
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

                uint32_t session_id;
                if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK ||
                    pqc_generate_session_id(&session_id) != 0) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Failed to create KEM/session material for Profile %d.\n",
                            profile_id);
                    usleep(500000);
                    continue;
                }
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                msg->magic = PQC_HS_MAGIC;
                msg->msg_type = PQC_HS_MSG_HELLO;
                msg->session_id = session_id;
                msg->profile_id = profile_id;
                msg->data_len = (uint16_t)pk_sz;
                memcpy(msg->payload, pk, pk_sz);

                pthread_mutex_lock(&g_key_mutex);
                if (b->local_priv && strlen(b->local_priv) > 0) {
                    if (my_priv) free(my_priv);
                    my_priv = strdup(b->local_priv);
                }
                if (b->peer_pub && strlen(b->peer_pub) > 0) {
                    if (peer_pub) free(peer_pub);
                    peer_pub = strdup(b->peer_pub);
                }
                size_t raw_priv_sz = 0;
                uint8_t raw_priv[8192];
                trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
                int sig_sz = 0;
                if (pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                                        msg->payload + pk_sz, &sig_sz) != TRF_PQC_OK) {
                    pthread_mutex_unlock(&g_key_mutex);
                    fprintf(stderr, "[PQC-HS-L3] Failed to sign HELLO for Profile %d.\n",
                            profile_id);
                    usleep(500000);
                    continue;
                }
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
                    fprintf(stderr,
                            "[PQC-WORKER-L3] Initiator Profile %d sending HELLO session %u (try: %d)...\n",
                            profile_id, session_id, retry_cnt + 1);
                    sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz + sig_sz, 0,
                           (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                    uint64_t start_rx = get_time_ms_hs();
                    while (g_dispatcher_running && get_time_ms_hs() - start_rx < 3000 && !b->key_ready && !b->thread_exit_sig) {
                        uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                        pqc_rx_pkt_info_t info;
                        int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                        if (rx_len > 0) {
                            const struct pqc_hs_msg *resp = NULL;
                            if (pqc_hs_validate_message(rx_buf, rx_len, &resp) == 0 &&
                                resp->magic == PQC_HS_MAGIC &&
                                resp->msg_type == PQC_HS_MSG_RESP &&
                                resp->session_id == session_id &&
                                pqc_hs_profile_matches(resp->profile_id,
                                                       profile_id)) {
                                pthread_mutex_lock(&g_key_mutex);
                                size_t raw_pub_sz = 0;
                                uint8_t raw_pub[8192];
                                trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                                pthread_mutex_unlock(&g_key_mutex);

                                if (pqc_hs_verify_message(raw_pub, raw_pub_sz, resp) == TRF_PQC_OK) {
                                    if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                        derive_traffic_key(ss, 32, derived_master);

                                        uint64_t callback_generation;

                                        pthread_mutex_lock(&g_key_mutex);
                                        handle_handshake_success(b, derived_master, "Initiator");
                                        callback_generation = b->config_generation;
                                        pthread_mutex_unlock(&g_key_mutex);

                                        sig_pqc_on_key_ready(profile_id,
                                                             derived_master,
                                                             callback_generation);
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
                        const struct pqc_hs_msg *msg = NULL;
                        if (pqc_hs_validate_message(rx_buf, rx_len, &msg) == 0 &&
                            msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                            pqc_hs_handle_responder_hello(b, sockfd, &peeraddr,
                                                          rx_buf, rx_len,
                                                          &my_priv, &peer_pub);
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
                    const struct pqc_hs_msg *msg = NULL;
                    if (pqc_hs_validate_message(rx_buf, rx_len, &msg) == 0 &&
                        msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                        pqc_hs_handle_responder_hello(b, sockfd, &peeraddr,
                                                      rx_buf, rx_len,
                                                      &my_priv, &peer_pub);
                    } else if (msg && msg->magic == PQC_HS_MAGIC &&
                               msg->msg_type == PQC_HS_MSG_KEEPALIVE &&
                               pqc_hs_profile_matches(msg->profile_id,
                                                      profile_id)) {
                        fprintf(stderr, "[PQC-HS-L3] Responder received KEEPALIVE for Profile %d. Verifying signature...\n", profile_id);
                        pthread_mutex_lock(&g_key_mutex);
                        if (b->peer_pub && strlen(b->peer_pub) > 0) {
                            if (peer_pub) free(peer_pub);
                            peer_pub = strdup(b->peer_pub);
                        }
                        if (b->local_priv && strlen(b->local_priv) > 0) {
                            if (my_priv) free(my_priv);
                            my_priv = strdup(b->local_priv);
                        }
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

void sig_pqc_bind_profile(int profile_id, const char *key_id, int role_mode,
                          const char *local_ip, const char *peer_ip,
                          const char *local_fg, const char *peer_fg,
                          const char *wan_ifname,
                          const char *local_priv, const char *local_pub,
                          const char *peer_pub,
                          uint64_t config_generation) {
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
        pqc_hs_clear_cache_locked(b);
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

            if (strcmp(b->local_ip, local_ip ? local_ip : "") != 0) changed = true;
            if (strcmp(b->peer_ip, peer_ip ? peer_ip : "") != 0) changed = true;
            if (strcmp(b->wan_ifname, wan_ifname ? wan_ifname : "") != 0) changed = true;
            if (strcmp(b->key_id, key_id ? key_id : "") != 0) changed = true;
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
                pqc_hs_clear_cache_locked(b);
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
        b->config_generation = config_generation;
        b->role_mode = role_mode;
        // Default assignment for is_initiator based on static roles
        if (role_mode == PQC_ROLE_INITIATOR) {
            b->is_initiator = true;
        } else if (role_mode == PQC_ROLE_RESPONDER) {
            b->is_initiator = false;
        } else {
            b->is_initiator = false; // Will be resolved dynamically
        }
        strncpy(b->local_ip, local_ip ? local_ip : "", sizeof(b->local_ip) - 1);
        b->local_ip[sizeof(b->local_ip) - 1] = '\0';
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
        snprintf(b->key_id, sizeof(b->key_id), "%s", key_id ? key_id : "");
        b->is_tunnel = true;

        if (b->local_priv) free(b->local_priv);
        if (b->local_pub) free(b->local_pub);
        if (b->peer_pub) free(b->peer_pub);

        b->local_priv = local_priv ? strdup(local_priv) : NULL;
        b->local_pub = local_pub ? strdup(local_pub) : NULL;
        b->peer_pub = deobf_peer;

        const char *role_str = (role_mode == PQC_ROLE_INITIATOR) ? "FORCE_INITIATOR" :
                               (role_mode == PQC_ROLE_RESPONDER) ? "FORCE_RESPONDER" : "DYNAMIC";
        fprintf(stderr, "[PQC-BIND] Profile %d bound in RAM (Key ID: %s, Local FG: %s, Peer FG: %s, Role Mode: %s, WAN: %s, Local IP: %s, Peer IP: %s).\n",
                profile_id, b->key_id, b->local_fingerprint, b->peer_fingerprint,
                role_str, b->wan_ifname, b->local_ip, b->peer_ip);

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

    // Fallback: key not in RAM, try loading directly from Vault
    char key_filename[64];
    snprintf(key_filename, sizeof(key_filename), "%s.key", clean_fg);
    if (sig_pqc_load_key_from_vault(key_filename) == 0) {
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
    }
    return -1;
}

int sig_pqc_load_key_from_vault(const char *fingerprint_key) {
    char pub_b64[8192] = "";
    char priv_b64[8192] = "";

    if (sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PUBLIC, fingerprint_key, pub_b64, sizeof(pub_b64)) == 0 &&
        sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PRIVATE, fingerprint_key, priv_b64, sizeof(priv_b64)) == 0) {
        
        char fg[16] = "";
        strncpy(fg, fingerprint_key, 8);
        fg[8] = '\0';
        sig_pqc_add_to_registry(fg, priv_b64, pub_b64);
        fprintf(stderr, "[PQC-VAULT-LOG] SUCCESS: Loaded local identity [%s] 100%% from Vault into RAM.\n", fg);
        return 0;
    }
    return -1;
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
            pqc_hs_clear_cache_locked(b);
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

int sig_pqc_snapshot_keys(int profile_id, uint8_t keys[3][32],
                          uint8_t key_ids[3], bool key_slots_valid[3]) {
    int idx = -1;

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].profile_id == profile_id) {
            idx = i;
            break;
        }
    }
    if (idx >= 0) {
        memcpy(keys, g_policy_bindings[idx].keys,
               KEY_SLOT_COUNT * PQC_TRAFFIC_KEY_SZ);
        memcpy(key_ids, g_policy_bindings[idx].key_ids, KEY_SLOT_COUNT);
        memcpy(key_slots_valid, g_policy_bindings[idx].key_slots_valid,
               KEY_SLOT_COUNT * sizeof(bool));
    }
    pthread_mutex_unlock(&g_key_mutex);
    return idx >= 0 ? 0 : -1;
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
