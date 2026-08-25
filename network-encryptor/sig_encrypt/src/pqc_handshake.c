#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include "../inc/pqc_l2_handshake.h"
#include "../inc/pqc_logger.h"
#include "../inc/pqc_vault.h"
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
#include <sys/random.h>
#include <net/if.h>
#include <endian.h>

#define PQC_RX_PKT_MAX     10000
#define KEY_ROTATION_INTERVAL_MS 30000 
#define L3_KEY_ROTATION_INTERVAL_MS 3000000
#define PQC_HS_GIVEUP_TIMEOUT_MS 15000
#define PQC_HS_REQUEST_RETRY_MS 1000
#define PQC_HS_REQUEST_DATA_SZ ((uint16_t)sizeof(uint64_t))
#define PQC_HS_KEEPALIVE_INTERVAL_MS 15000
#define PQC_HS_KEEPALIVE_MISSED_LIMIT 3
#define PQC_HS_KEEPALIVE_TIMEOUT_MS \
    (PQC_HS_KEEPALIVE_INTERVAL_MS * PQC_HS_KEEPALIVE_MISSED_LIMIT)
#define PQC_HS_AUTO_RETRY_INTERVAL_MS 15000
#define PQC_HS_DISPATCHER_RETRY_MS 5000
#define PQC_HS_WORKER_SUPERVISOR_MS 5000
#define PQC_HS_WORKER_STOP_TIMEOUT_MS 2000
#define PQC_HS_KEY_FINGERPRINT_SZ 32
#define PQC_HS_STATE_READY 1
#define PQC_HS_STATE_FAILED 2
#define PQC_HS_STATE_HANDSHAKING 3

typedef struct {
    uint8_t state;
    uint8_t role;
    uint8_t key_id;
    uint8_t key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
    uint8_t epoch_be[sizeof(uint64_t)];
    uint8_t sequence_be[sizeof(uint64_t)];
} pqc_hs_keepalive_wire_t;

typedef struct {
    uint8_t state;
    uint8_t role;
    uint8_t key_id;
    uint8_t key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
    uint64_t epoch;
    uint64_t sequence;
} pqc_hs_keepalive_status_t;

#define PQC_HS_KEEPALIVE_DATA_SZ \
    ((uint16_t)sizeof(pqc_hs_keepalive_wire_t))

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

/* g_dispatcher_running is the lifetime request shared by L2/L3 workers.
 * The remaining flags describe the L3 UDP listener itself, so a failed bind
 * cannot leave the system believing that receive dispatch is still alive. */
static volatile bool g_dispatcher_running = false;
static bool g_udp_dispatcher_alive = false;
static bool g_udp_dispatcher_starting = false;
static uint64_t g_udp_dispatcher_next_retry_time = 0;

static l2_dispatcher_t g_l2_dispatchers[MAX_L2_DISPATCHERS];
static int g_l2_dispatchers_count = 0;

static int pqc_policy_rx_recv(policy_key_binding_t *b, uint8_t *buf, int buf_sz, pqc_rx_pkt_info_t *info, int timeout_ms);
static void* pqc_policy_handshake_worker_run(void *arg);
static int pqc_ensure_udp_dispatcher_running(void);

/* g_key_mutex must be held.  Starting one policy never waits for another
 * policy, which keeps the policy state machines independent. */
static int pqc_start_policy_worker_locked(policy_key_binding_t *b) {
    int create_rc;

    if (!b || b->thread_started || b->thread_exit_sig ||
        !b->local_priv || !b->local_pub || !b->peer_pub)
        return 0;

    b->thread_started = true;
    create_rc = pthread_create(&b->thread_id, NULL,
                               pqc_policy_handshake_worker_run, b);
    if (create_rc != 0) {
        b->thread_started = false;
        fprintf(stderr,
                "[PQC-HS] ERROR: Failed to spawn Handshake Worker for Policy %d: %s\n",
                b->policy_id, strerror(create_rc));
        return -create_rc;
    }

    pthread_detach(b->thread_id);
    fprintf(stderr,
            "[PQC-HS] Spawned independent Handshake Worker for Policy %d (Profile %d)\n",
            b->policy_id, b->profile_id);
    return 0;
}

static void pqc_supervise_l3_workers(void) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        policy_key_binding_t *b = &g_policy_bindings[i];

        if (!g_policy_bindings_active[i] || !b->is_tunnel ||
            b->thread_started || b->thread_exit_sig)
            continue;
        pqc_start_policy_worker_locked(b);
    }
    pthread_mutex_unlock(&g_key_mutex);
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

static int pqc_generate_request_id(uint64_t *request_id) {
    uint64_t value = 0;

    if (!request_id) return -EINVAL;

    do {
        size_t filled = 0;

        while (filled < sizeof(value)) {
            ssize_t n = getrandom((uint8_t *)&value + filled,
                                  sizeof(value) - filled, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                return -errno;
            }
            if (n == 0) return -EIO;
            filled += (size_t)n;
        }
    } while (value == 0);

    *request_id = value;
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

/* Authentication uses a caller-owned snapshot.  ML-DSA verification must not
 * hold g_key_mutex because that would serialize every PQC policy behind one
 * slow or invalid packet. */
static int pqc_hs_verify_l3_request(int policy_id, bool is_tunnel,
                                    bool is_initiator,
                                    const char *peer_pub,
                                    const struct pqc_hs_msg *msg,
                                    uint64_t *request_id) {
    uint8_t raw_pub[8192];
    uint64_t request_id_be;
    size_t raw_pub_sz = 0;

    if (!msg || !request_id || !is_tunnel ||
        msg->magic != PQC_HS_MAGIC || msg->msg_type != PQC_HS_MSG_POKE ||
        msg->session_id == 0 ||
        msg->policy_id != (uint32_t)policy_id ||
        msg->data_len != PQC_HS_REQUEST_DATA_SZ || msg->sig_len == 0 ||
        !is_initiator || !peer_pub || peer_pub[0] == '\0')
        return -EINVAL;

    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
    if (raw_pub_sz == 0 ||
        pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK)
        return -EKEYREJECTED;

    memcpy(&request_id_be, msg->payload, sizeof(request_id_be));
    *request_id = be64toh(request_id_be);
    return *request_id ? 0 : -EINVAL;
}

static int pqc_hs_send_l3_handshake_request(
    policy_key_binding_t *b, int sockfd,
    const struct sockaddr_in *peeraddr, const char *my_priv) {
    uint8_t request_buf[PQC_HS_MSG_MAX_SZ];
    uint8_t raw_priv[8192];
    struct pqc_hs_msg *request = (struct pqc_hs_msg *)request_buf;
    uint64_t request_id;
    uint64_t request_id_be;
    size_t raw_priv_sz = 0;
    size_t request_len;
    int sig_sz = 0;
    ssize_t sent;

    if (!b || sockfd < 0 || !peeraddr || !my_priv || my_priv[0] == '\0')
        return -EINVAL;

    pthread_mutex_lock(&g_key_mutex);
    request_id = b->local_request_id;
    pthread_mutex_unlock(&g_key_mutex);
    if (!request_id) {
        int rc = pqc_generate_request_id(&request_id);
        if (rc != 0) return rc;

        pthread_mutex_lock(&g_key_mutex);
        if (!b->local_request_id) b->local_request_id = request_id;
        request_id = b->local_request_id;
        pthread_mutex_unlock(&g_key_mutex);
    }

    memset(request_buf, 0, sizeof(request_buf));
    request->magic = PQC_HS_MAGIC;
    request->msg_type = PQC_HS_MSG_POKE;
    request->policy_id = (uint32_t)b->policy_id;
    request->data_len = PQC_HS_REQUEST_DATA_SZ;
    if (pqc_generate_session_id(&request->session_id) != 0)
        return errno ? -errno : -EIO;

    request_id_be = htobe64(request_id);
    memcpy(request->payload, &request_id_be, sizeof(request_id_be));
    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
    if (raw_priv_sz == 0 ||
        pqc_hs_sign_message(raw_priv, raw_priv_sz, request,
                            request->payload + request->data_len,
                            &sig_sz) != TRF_PQC_OK ||
        sig_sz <= 0 || (size_t)sig_sz > UINT16_MAX)
        return -EKEYREJECTED;

    request_len = sizeof(*request) + request->data_len + (size_t)sig_sz;
    if (request_len > sizeof(request_buf)) return -EMSGSIZE;
    request->sig_len = (uint16_t)sig_sz;

    sent = sendto(sockfd, request, request_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    if (sent != (ssize_t)request_len)
        return sent < 0 ? -errno : -EIO;
    return 0;
}

static uint8_t pqc_hs_l3_state_locked(const policy_key_binding_t *b) {
    if ((!b->handshake_give_up && b->handshake_start_time != 0 &&
         !b->key_ready) ||
        (!b->rotation_give_up && b->rotation_start_time != 0))
        return PQC_HS_STATE_HANDSHAKING;
    if (b->key_ready && b->key_slots_valid[KEY_SLOT_CURRENT])
        return PQC_HS_STATE_READY;
    return PQC_HS_STATE_FAILED;
}

static int pqc_hs_l3_key_fingerprint_locked(
    const policy_key_binding_t *b,
    uint8_t fingerprint[PQC_HS_KEY_FINGERPRINT_SZ]) {
    if (!b || !fingerprint || pqc_hs_l3_state_locked(b) != PQC_HS_STATE_READY)
        return -EINVAL;

    return trf_calculate_digest(DIGEST_TYPE_SHA256,
                                b->keys[KEY_SLOT_CURRENT],
                                PQC_TRAFFIC_KEY_SZ,
                                fingerprint) == TRF_PQC_OK ? 0 : -EIO;
}

static int pqc_hs_verify_l3_keepalive(
    int policy_id, bool is_tunnel, bool is_initiator,
    const char *peer_pub, const struct pqc_hs_msg *msg,
    pqc_hs_keepalive_status_t *status) {
    const pqc_hs_keepalive_wire_t *wire;
    uint8_t raw_pub[8192];
    uint64_t epoch_be;
    uint64_t sequence_be;
    size_t raw_pub_sz = 0;
    bool fingerprint_is_zero = true;

    if (!msg || !status || !is_tunnel ||
        msg->magic != PQC_HS_MAGIC ||
        msg->msg_type != PQC_HS_MSG_KEEPALIVE ||
        msg->session_id == 0 ||
        msg->policy_id != (uint32_t)policy_id ||
        msg->data_len != PQC_HS_KEEPALIVE_DATA_SZ || msg->sig_len == 0 ||
        !peer_pub || peer_pub[0] == '\0')
        return -EINVAL;

    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
    if (raw_pub_sz == 0 ||
        pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK)
        return -EKEYREJECTED;

    wire = (const pqc_hs_keepalive_wire_t *)msg->payload;
    if ((wire->state != PQC_HS_STATE_READY &&
         wire->state != PQC_HS_STATE_FAILED &&
         wire->state != PQC_HS_STATE_HANDSHAKING) ||
        wire->role > 1 || wire->role == (uint8_t)is_initiator)
        return -EPROTO;

    memcpy(&epoch_be, wire->epoch_be, sizeof(epoch_be));
    memcpy(&sequence_be, wire->sequence_be, sizeof(sequence_be));
    status->epoch = be64toh(epoch_be);
    status->sequence = be64toh(sequence_be);
    if (status->epoch == 0 || status->sequence == 0) return -EINVAL;

    status->state = wire->state;
    status->role = wire->role;
    status->key_id = wire->key_id;
    memcpy(status->key_fingerprint, wire->key_fingerprint,
           sizeof(status->key_fingerprint));

    for (size_t i = 0; i < sizeof(status->key_fingerprint); i++) {
        if (status->key_fingerprint[i] != 0) {
            fingerprint_is_zero = false;
            break;
        }
    }
    if (status->state == PQC_HS_STATE_READY &&
        (status->key_id == 0 || fingerprint_is_zero))
        return -EPROTO;
    return 0;
}

static int pqc_hs_send_l3_keepalive(
    policy_key_binding_t *b, int sockfd,
    const struct sockaddr_in *peeraddr, const char *my_priv) {
    uint8_t keepalive_buf[PQC_HS_MSG_MAX_SZ];
    uint8_t raw_priv[8192];
    uint8_t key_material[PQC_TRAFFIC_KEY_SZ];
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)keepalive_buf;
    pqc_hs_keepalive_wire_t *wire;
    uint64_t epoch;
    uint64_t sequence;
    uint64_t value_be;
    uint8_t state;
    uint8_t role;
    uint8_t key_id = 0;
    size_t raw_priv_sz = 0;
    size_t msg_len;
    int sig_sz = 0;
    ssize_t sent;

    if (!b || sockfd < 0 || !peeraddr || !my_priv || my_priv[0] == '\0')
        return -EINVAL;

    pthread_mutex_lock(&g_key_mutex);
    if (!b->keepalive_enabled) {
        pthread_mutex_unlock(&g_key_mutex);
        return -EAGAIN;
    }
    epoch = b->local_request_id;
    pthread_mutex_unlock(&g_key_mutex);

    if (!epoch) {
        int rc = pqc_generate_request_id(&epoch);
        if (rc != 0) return rc;

        pthread_mutex_lock(&g_key_mutex);
        if (!b->local_request_id) {
            b->local_request_id = epoch;
            b->local_keepalive_seq = 0;
        }
        epoch = b->local_request_id;
        pthread_mutex_unlock(&g_key_mutex);
    }

    pthread_mutex_lock(&g_key_mutex);
    if (!b->keepalive_enabled) {
        pthread_mutex_unlock(&g_key_mutex);
        return -EAGAIN;
    }
    epoch = b->local_request_id;
    if (!epoch) {
        pthread_mutex_unlock(&g_key_mutex);
        return -EAGAIN;
    }
    state = pqc_hs_l3_state_locked(b);
    role = b->is_initiator ? 1 : 0;
    sequence = ++b->local_keepalive_seq;
    if (sequence == 0) sequence = ++b->local_keepalive_seq;
    if (state == PQC_HS_STATE_READY) {
        key_id = b->key_ids[KEY_SLOT_CURRENT];
        memcpy(key_material, b->keys[KEY_SLOT_CURRENT], sizeof(key_material));
    } else {
        memset(key_material, 0, sizeof(key_material));
    }
    pthread_mutex_unlock(&g_key_mutex);

    memset(keepalive_buf, 0, sizeof(keepalive_buf));
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_KEEPALIVE;
    msg->policy_id = (uint32_t)b->policy_id;
    msg->data_len = PQC_HS_KEEPALIVE_DATA_SZ;
    if (pqc_generate_session_id(&msg->session_id) != 0)
        return errno ? -errno : -EIO;

    wire = (pqc_hs_keepalive_wire_t *)msg->payload;
    wire->state = state;
    wire->role = role;
    wire->key_id = key_id;
    if (state == PQC_HS_STATE_READY &&
        trf_calculate_digest(DIGEST_TYPE_SHA256, key_material,
                             sizeof(key_material),
                             wire->key_fingerprint) != TRF_PQC_OK)
        return -EIO;
    value_be = htobe64(epoch);
    memcpy(wire->epoch_be, &value_be, sizeof(value_be));
    value_be = htobe64(sequence);
    memcpy(wire->sequence_be, &value_be, sizeof(value_be));

    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
    if (raw_priv_sz == 0 ||
        pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                            msg->payload + msg->data_len,
                            &sig_sz) != TRF_PQC_OK ||
        sig_sz <= 0 || (size_t)sig_sz > UINT16_MAX)
        return -EKEYREJECTED;
    msg->sig_len = (uint16_t)sig_sz;

    msg_len = sizeof(*msg) + msg->data_len + (size_t)sig_sz;
    if (msg_len > sizeof(keepalive_buf)) return -EMSGSIZE;
    sent = sendto(sockfd, msg, msg_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    if (sent != (ssize_t)msg_len)
        return sent < 0 ? -errno : -EIO;
    return 0;
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
    bool was_ready;
    int policy_id;
    int promoted_key_id;
    char key_id[sizeof(b->key_id)];

    pthread_mutex_lock(&g_key_mutex);
    was_ready = b->key_ready;
    policy_id = b->policy_id;
    strncpy(key_id, b->key_id, sizeof(key_id) - 1);
    key_id[sizeof(key_id) - 1] = '\0';

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
    b->giveup_logged = false;
    if (b->is_tunnel) {
        b->keepalive_enabled = true;
        b->keepalive_monitor_start_time = get_time_ms_hs();
        b->last_keepalive_rx_time = 0;
        b->next_auto_retry_time = 0;
    }

    int idx = b - g_policy_bindings;
    if (idx >= 0 && idx < MAX_POLICY_BINDINGS) {
        g_policy_key_version[idx]++;
    }
    promoted_key_id = b->key_ids[KEY_SLOT_CURRENT];
    pthread_mutex_unlock(&g_key_mutex);

    sig_pqc_write_log(policy_id, key_id, PQC_LOG_LEVEL_INFO,
                      PQC_LOG_STATUS_SUCCESS,
                      was_ready ? "Session key updated."
                                : "Secure session established.");

    fprintf(stderr, "[PQC-HS] %s Handshake SUCCESS for Policy %d. Promoted new key ID: %d to CURRENT. Key prefix: %02X%02X%02X%02X...\n",
            role, policy_id, promoted_key_id,
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
                "[PQC-HS-L3] Failed to send RESP for Policy %d, session %u: %s\n",
                b->policy_id, session_id,
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
            memset(b->hs_cache[cache_slot].master_key, 0,
                   sizeof(b->hs_cache[cache_slot].master_key));
            promote_now = true;
        }
        pthread_mutex_unlock(&g_key_mutex);
    }

    if (promote_now) {
        handle_handshake_success(b, master_key, "Responder");
        forwarder_pre_diversify_pqc_keys(b->profile_id);
    }

    fprintf(stderr,
            "[PQC-HS-L3] Responder %s RESP for Policy %d, session %u%s.\n",
            replay ? "replayed cached" : "sent new",
            b->policy_id, session_id,
            already_promoted ? " (key unchanged)" : "");
    return 0;
}

static int pqc_hs_handle_l3_responder_hello(policy_key_binding_t *b,
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
        msg->policy_id != (uint32_t)b->policy_id || msg->session_id == 0) {
        fprintf(stderr, "[PQC-HS-L3] Rejected malformed/mismatched HELLO for Policy %d.\n",
                b->policy_id);
        return -1;
    }

    if (trf_calculate_digest(DIGEST_TYPE_SHA256, rx_buf, rx_len, hello_hash) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] Failed to fingerprint HELLO for Policy %d.\n",
                b->policy_id);
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
                "[PQC-HS-L3] Rejected HELLO reusing session %u with different content for Policy %d.\n",
                msg->session_id, b->policy_id);
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
        fprintf(stderr, "[PQC-HS-L3] Missing responder authentication keys for Policy %d.\n",
                b->policy_id);
        return -1;
    }
    free(*my_priv);
    free(*peer_pub);
    *my_priv = new_my_priv;
    *peer_pub = new_peer_pub;

    trf_base64_decode(*peer_pub, raw_pub, &raw_pub_sz);
    if (pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK) {
        fprintf(stderr,
                "[PQC-HS-L3] HELLO signature verification failed for Policy %d, session %u.\n",
                b->policy_id, msg->session_id);
        sig_pqc_write_log(b->policy_id, b->key_id, PQC_LOG_LEVEL_ERROR,
                          PQC_LOG_STATUS_FAILED,
                          "Handshake signature verification failed. Mismatched authentication keys.");
        return -1;
    }

    if (trf_kem_encapsulate(msg->payload, msg->data_len, ct, &ct_sz, ss) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] KEM encapsulation failed for Policy %d, session %u.\n",
                b->policy_id, msg->session_id);
        return -1;
    }

    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)response_buf;
    resp->magic = PQC_HS_MAGIC;
    resp->msg_type = PQC_HS_MSG_RESP;
    resp->session_id = msg->session_id;
    resp->policy_id = (uint32_t)b->policy_id;
    resp->data_len = (uint16_t)ct_sz;
    resp->sig_len = 0;
    memcpy(resp->payload, ct, (size_t)ct_sz);

    trf_base64_decode(*my_priv, raw_priv, &raw_priv_sz);
    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, resp,
                            resp->payload + ct_sz, &sig_sz) != TRF_PQC_OK) {
        fprintf(stderr, "[PQC-HS-L3] Failed to sign RESP for Policy %d, session %u.\n",
                b->policy_id, msg->session_id);
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

static void initiate_l3_key_rotation(policy_key_binding_t *b, int sockfd,
                                     const struct sockaddr_in *peeraddr,
                                     char *my_priv, char *peer_pub,
                                     int profile_id) {
    uint8_t pk[2048], sk[4096], ss[128];
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];
    int pk_sz = 0, sk_sz = 0;
    uint32_t session_id;

    fprintf(stderr,
            "[PQC-HS-L3] Proactively initiating periodic key rotation for Policy %d...\n",
            b->policy_id);

    if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK ||
        pqc_generate_session_id(&session_id) != 0) {
        fprintf(stderr,
                "[PQC-HS-L3] Failed to create rotation KEM/session material for Policy %d.\n",
                b->policy_id);
        return;
    }

    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_HELLO;
    msg->session_id = session_id;
    msg->policy_id = (uint32_t)b->policy_id;
    msg->sig_len = 0;
    msg->data_len = (uint16_t)pk_sz;
    memcpy(msg->payload, pk, (size_t)pk_sz);

    size_t raw_priv_sz = 0;
    uint8_t raw_priv[8192];
    int sig_sz = 0;
    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                            msg->payload + pk_sz, &sig_sz) != TRF_PQC_OK) {
        fprintf(stderr,
                "[PQC-HS-L3] Failed to sign rotation HELLO for Policy %d.\n",
                b->policy_id);
        return;
    }
    msg->sig_len = (uint16_t)sig_sz;

    int payload_tot_sz = (int)sizeof(*msg) + pk_sz + sig_sz;
    uint64_t rotation_started = get_time_ms_hs();
    int retry_cnt = 0;

    while (g_dispatcher_running && !b->thread_exit_sig &&
           get_time_ms_hs() - rotation_started < PQC_HS_GIVEUP_TIMEOUT_MS) {
        ssize_t sent = sendto(sockfd, buffer, (size_t)payload_tot_sz, 0,
                              (const struct sockaddr *)peeraddr,
                              sizeof(*peeraddr));
        fprintf(stderr,
                "[PQC-HS-L3] Rotation HELLO Policy %d, session %u, try %d%s.\n",
                b->policy_id, session_id, ++retry_cnt,
                sent == payload_tot_sz ? " sent" : " send failed");

        uint64_t start_rx = get_time_ms_hs();
        while (g_dispatcher_running && !b->thread_exit_sig &&
               get_time_ms_hs() - start_rx < 3000) {
            uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
            pqc_rx_pkt_info_t info;
            const struct pqc_hs_msg *resp = NULL;
            int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf),
                                            &info, 200);

            if (rx_len > 0 &&
                pqc_hs_validate_message(rx_buf, rx_len, &resp) == 0 &&
                resp->magic == PQC_HS_MAGIC &&
                resp->msg_type == PQC_HS_MSG_RESP &&
                resp->session_id == session_id &&
                resp->policy_id == (uint32_t)b->policy_id) {
                size_t raw_pub_sz = 0;
                uint8_t raw_pub[8192];
                trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);

                if (pqc_hs_verify_message(raw_pub, raw_pub_sz, resp) == TRF_PQC_OK &&
                    trf_kem_decapsulate(sk, sk_sz, resp->payload,
                                        resp->data_len, ss) == TRF_PQC_OK) {
                    uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                    derive_traffic_key(ss, 32, derived_master);

                    handle_handshake_success(b, derived_master, "Initiator");

                    forwarder_pre_diversify_pqc_keys(profile_id);
                    return;
                }
            }
            usleep(10000);
        }
    }

    fprintf(stderr,
            "[PQC-HS-L3] Key rotation handshake timed out or failed for Policy %d.\n",
            b->policy_id);
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

                        handle_handshake_success(b, derived_master, "Initiator");

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

static void pqc_flush_l3_rx_queue(policy_key_binding_t *b) {
    pthread_mutex_lock(&b->rx_mutex);
    for (int q = 0; q < PQC_RX_QUEUE_SIZE; q++) {
        free(b->rx_queue[q]);
        b->rx_queue[q] = NULL;
        b->rx_len[q] = 0;
    }
    b->rx_head = 0;
    b->rx_tail = 0;
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
            if (msg->msg_type == PQC_HS_MSG_KEEPALIVE && b->is_tunnel) {
                const struct pqc_hs_msg *validated_msg = NULL;
                pqc_hs_keepalive_status_t peer_status;
                uint8_t local_state;
                uint8_t local_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
                const char *recovery_reason = NULL;
                char *peer_pub_snapshot;
                bool is_tunnel_snapshot;
                bool is_initiator_snapshot;
                int binding_policy_id;
                int verify_rc;

                memset(&peer_status, 0, sizeof(peer_status));
                if (pqc_hs_validate_message(payload, len,
                                            &validated_msg) != 0) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Rejected malformed KEM key keepalive for Policy %d.\n",
                            b->policy_id);
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }

                binding_policy_id = b->policy_id;
                is_tunnel_snapshot = b->is_tunnel;
                is_initiator_snapshot = b->is_initiator;
                peer_pub_snapshot = b->peer_pub ? strdup(b->peer_pub) : NULL;
                pthread_mutex_unlock(&g_key_mutex);

                verify_rc = pqc_hs_verify_l3_keepalive(
                    binding_policy_id, is_tunnel_snapshot,
                    is_initiator_snapshot, peer_pub_snapshot,
                    validated_msg, &peer_status);
                if (verify_rc != 0) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Rejected unauthenticated/invalid KEM key keepalive for Policy %d: %s.\n",
                            binding_policy_id, strerror(-verify_rc));
                    free(peer_pub_snapshot);
                    return;
                }

                pthread_mutex_lock(&g_key_mutex);
                if (b->policy_id != binding_policy_id ||
                    b->is_tunnel != is_tunnel_snapshot ||
                    b->is_initiator != is_initiator_snapshot ||
                    !b->peer_pub || !peer_pub_snapshot ||
                    strcmp(b->peer_pub, peer_pub_snapshot) != 0) {
                    free(peer_pub_snapshot);
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }
                free(peer_pub_snapshot);

                if (peer_status.epoch == b->peer_keepalive_epoch &&
                    peer_status.sequence <= b->peer_keepalive_seq) {
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }
                b->peer_keepalive_epoch = peer_status.epoch;
                b->peer_keepalive_seq = peer_status.sequence;
                b->last_keepalive_rx_time = get_time_ms_hs();
                b->keepalive_monitor_start_time =
                    b->last_keepalive_rx_time;

                local_state = pqc_hs_l3_state_locked(b);
                if (local_state == PQC_HS_STATE_HANDSHAKING ||
                    peer_status.state == PQC_HS_STATE_HANDSHAKING) {
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }

                if (local_state == PQC_HS_STATE_READY &&
                    peer_status.state == PQC_HS_STATE_READY) {
                    if (pqc_hs_l3_key_fingerprint_locked(
                            b, local_fingerprint) == 0 &&
                        memcmp(local_fingerprint,
                               peer_status.key_fingerprint,
                               sizeof(local_fingerprint)) == 0) {
                        pthread_mutex_unlock(&g_key_mutex);
                        return;
                    }
                    recovery_reason = "peer key fingerprint mismatch";
                } else if (local_state == PQC_HS_STATE_FAILED) {
                    recovery_reason = "local policy has no usable key";
                } else if (peer_status.state == PQC_HS_STATE_FAILED) {
                    recovery_reason = "peer reported failed key state";
                }

                if (!recovery_reason) {
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }

                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->giveup_logged = false;
                b->key_ready = false;
                b->next_auto_retry_time = 0;
                b->keepalive_monitor_start_time = get_time_ms_hs();
                if (b->is_initiator) {
                    b->send_poke = false;
                } else {
                    b->local_request_id = 0;
                    b->local_keepalive_seq = 0;
                    b->send_poke = true;
                }
                pqc_hs_clear_cache_locked(b);
                pqc_flush_l3_rx_queue(b);
                fprintf(stderr,
                        "[PQC-HS-L3] KEM key keepalive triggered automatic recovery for Policy %d (%s). Role=%s.\n",
                        b->policy_id, recovery_reason,
                        b->is_initiator ? "Initiator" : "Responder");
                pthread_mutex_unlock(&g_key_mutex);
                return;
            } else if (msg->msg_type == PQC_HS_MSG_POKE) {
                if (b->is_tunnel) {
                    const struct pqc_hs_msg *validated_msg = NULL;
                    uint64_t request_id = 0;
                    char *peer_pub_snapshot;
                    bool is_tunnel_snapshot;
                    bool is_initiator_snapshot;
                    int binding_policy_id;
                    int verify_rc;

                    if (pqc_hs_validate_message(payload, len,
                                                &validated_msg) != 0) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Rejected malformed handshake request for Policy %d.\n",
                                b->policy_id);
                        pthread_mutex_unlock(&g_key_mutex);
                        return;
                    }

                    binding_policy_id = b->policy_id;
                    is_tunnel_snapshot = b->is_tunnel;
                    is_initiator_snapshot = b->is_initiator;
                    peer_pub_snapshot = b->peer_pub ? strdup(b->peer_pub) : NULL;
                    pthread_mutex_unlock(&g_key_mutex);

                    verify_rc = pqc_hs_verify_l3_request(
                        binding_policy_id, is_tunnel_snapshot,
                        is_initiator_snapshot, peer_pub_snapshot,
                        validated_msg, &request_id);
                    if (verify_rc != 0) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Rejected unauthenticated/invalid handshake request for Policy %d: %s.\n",
                                binding_policy_id, strerror(-verify_rc));
                        free(peer_pub_snapshot);
                        return;
                    }

                    pthread_mutex_lock(&g_key_mutex);
                    if (b->policy_id != binding_policy_id ||
                        b->is_tunnel != is_tunnel_snapshot ||
                        b->is_initiator != is_initiator_snapshot ||
                        !b->peer_pub || !peer_pub_snapshot ||
                        strcmp(b->peer_pub, peer_pub_snapshot) != 0) {
                        free(peer_pub_snapshot);
                        pthread_mutex_unlock(&g_key_mutex);
                        return;
                    }
                    free(peer_pub_snapshot);
                    if (request_id == b->peer_request_id) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Ignored duplicate handshake request %016llx for Policy %d.\n",
                                (unsigned long long)request_id, b->policy_id);
                        pthread_mutex_unlock(&g_key_mutex);
                        return;
                    }

                    b->peer_request_id = request_id;
                    b->handshake_give_up = false;
                    b->handshake_start_time = 0;
                    b->rotation_give_up = false;
                    b->rotation_start_time = 0;
                    b->giveup_logged = false;
                    b->key_ready = false;
                    b->next_auto_retry_time = 0;
                    b->last_keepalive_rx_time = 0;
                    b->keepalive_monitor_start_time = get_time_ms_hs();
                    pqc_hs_clear_cache_locked(b);
                    pqc_flush_l3_rx_queue(b);
                    fprintf(stderr,
                            "[PQC-HS-L3] Accepted authenticated responder request %016llx. Restarting initiator handshake for Policy %d.\n",
                            (unsigned long long)request_id, b->policy_id);
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }

                /* Preserve the existing unsigned POKE behavior for L2. */
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->giveup_logged = false;
                b->key_ready = false;
                fprintf(stderr, "[PQC-HS] Received POKE message. Resetting handshake retry for Policy %d.\n", policy_id);
                pthread_mutex_unlock(&g_key_mutex);
                return;
            } else if (msg->msg_type == PQC_HS_MSG_HELLO) {
                if (b->handshake_give_up) {
                    b->handshake_give_up = false;
                    b->handshake_start_time = 0;
                    b->rotation_give_up = false;
                    b->rotation_start_time = 0;
                    b->giveup_logged = false;
                    b->key_ready = false;
                    if (b->is_tunnel) {
                        b->next_auto_retry_time = 0;
                        b->last_keepalive_rx_time = 0;
                        b->keepalive_monitor_start_time = get_time_ms_hs();
                        pqc_flush_l3_rx_queue(b);
                    }
                    fprintf(stderr, "[PQC-HS] Received HELLO message while asleep. Waking up Responder for Policy %d.\n", policy_id);
                }
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
        pthread_mutex_lock(&g_key_mutex);
        g_udp_dispatcher_alive = false;
        g_udp_dispatcher_starting = false;
        g_udp_dispatcher_next_retry_time =
            get_time_ms_hs() + PQC_HS_DISPATCHER_RETRY_MS;
        pthread_mutex_unlock(&g_key_mutex);
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
        pthread_mutex_lock(&g_key_mutex);
        g_udp_dispatcher_alive = false;
        g_udp_dispatcher_starting = false;
        g_udp_dispatcher_next_retry_time =
            get_time_ms_hs() + PQC_HS_DISPATCHER_RETRY_MS;
        pthread_mutex_unlock(&g_key_mutex);
        return NULL;
    }

    uint8_t buffer[PQC_HS_MSG_MAX_SZ];
    struct sockaddr_in clientaddr;
    socklen_t addr_len = sizeof(clientaddr);

    pthread_mutex_lock(&g_key_mutex);
    g_udp_dispatcher_alive = true;
    g_udp_dispatcher_starting = false;
    g_udp_dispatcher_next_retry_time = 0;
    pthread_mutex_unlock(&g_key_mutex);

    fprintf(stderr, "[PQC-DISPATCHER] UDP Listener running on port %d\n", PQC_HS_PORT);

    uint64_t next_worker_supervisor_time = 0;
    while (g_dispatcher_running) {
        uint64_t now = get_time_ms_hs();
        int n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addr_len);
        if (n > 0) {
            sig_pqc_feed_rx_packet(buffer, n, NULL);
        } else {
            usleep(10000);
        }
        if (next_worker_supervisor_time == 0 ||
            now >= next_worker_supervisor_time) {
            pqc_supervise_l3_workers();
            next_worker_supervisor_time =
                now + PQC_HS_WORKER_SUPERVISOR_MS;
        }
    }

    close(sockfd);
    pthread_mutex_lock(&g_key_mutex);
    g_udp_dispatcher_alive = false;
    g_udp_dispatcher_starting = false;
    g_udp_dispatcher_next_retry_time =
        get_time_ms_hs() + PQC_HS_DISPATCHER_RETRY_MS;
    pthread_mutex_unlock(&g_key_mutex);
    return NULL;
}

static int pqc_ensure_udp_dispatcher_running(void) {
    pthread_t udp_tid;
    uint64_t now = get_time_ms_hs();
    int create_rc;

    pthread_mutex_lock(&g_key_mutex);
    g_dispatcher_running = true;
    if (g_udp_dispatcher_alive || g_udp_dispatcher_starting) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }
    if (g_udp_dispatcher_next_retry_time != 0 &&
        now < g_udp_dispatcher_next_retry_time) {
        pthread_mutex_unlock(&g_key_mutex);
        return -EAGAIN;
    }

    g_udp_dispatcher_starting = true;
    g_udp_dispatcher_next_retry_time = now + PQC_HS_DISPATCHER_RETRY_MS;
    create_rc = pthread_create(&udp_tid, NULL,
                               pqc_udp_dispatcher_thread, NULL);
    if (create_rc != 0) {
        g_udp_dispatcher_starting = false;
        fprintf(stderr,
                "[PQC-HS] ERROR starting UDP dispatcher thread: %s\n",
                strerror(create_rc));
        pthread_mutex_unlock(&g_key_mutex);
        return -create_rc;
    }
    pthread_detach(udp_tid);
    pthread_mutex_unlock(&g_key_mutex);
    return 0;
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
    uint64_t next_l3_request_time = 0;
    uint64_t next_l3_keepalive_time = 0;
    uint64_t next_dispatcher_check_time = 0;
    uint8_t last_l3_keepalive_state = 0;

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
        pthread_mutex_lock(&g_key_mutex);
        b->thread_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return NULL;
    }

    bool is_bridge_mode = (strlen(wan_ifname) > 0 && 
                          (strlen(peer_ip) == 0 || strcmp(peer_ip, "0.0.0.0") == 0));
    if (b->is_tunnel) {
        is_bridge_mode = false;
    }

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
            pthread_mutex_lock(&g_key_mutex);
            b->thread_started = false;
            pthread_mutex_unlock(&g_key_mutex);
            return NULL;
        }

        while (g_dispatcher_running && !b->thread_exit_sig) {
            if (b->handshake_give_up) {
                usleep(500000);
                continue;
            }
            if (!b->key_ready) {
                if (b->role_mode == PQC_ROLE_DYNAMIC || is_initiator) {
                    fprintf(stderr, "[PQC-WORKER] Policy %d: Initiator peer MAC discovery...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                        if (pqc_l2_discover_peer_mac(&peer, 5) == 0) {
                            break;
                        }
                        usleep(1000000);
                    }

                    if (!g_dispatcher_running || b->thread_exit_sig) {
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

                        while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
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

                                                handle_handshake_success(b, derived_master, "Initiator");

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
                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = get_time_ms_hs();
                    }
                    fprintf(stderr, "[PQC-WORKER-L2] Responder (Policy %d) listening for HELLO...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                        if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                            if (!b->giveup_logged) {
                                fprintf(stderr, "[PQC-HS-L2] Responder timed out waiting for HELLO on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake timeout. No HELLO received from Peer.");
                                b->giveup_logged = true;
                            }
                            b->handshake_give_up = true;
                            break;
                        }
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

                                        handle_handshake_success(b, derived_master, "Responder");

                                        forwarder_pre_diversify_pqc_keys(profile_id);
                                    } else {
                                        fprintf(stderr, "[PQC-HS-L2] Handshake signature verification failed for Policy %d. Mismatched authentication keys or packet corrupted.\n", policy_id);
                                        sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake signature verification failed. Mismatched authentication keys.");
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
                            if (now - b->rotation_start_time > 15000) {
                                fprintf(stderr, "[PQC-HS-L2] Key rotation timed out after 15 seconds. Giving up on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed.");
                                pthread_mutex_lock(&g_key_mutex);
                                b->key_ready = false;
                                b->handshake_give_up = true;
                                b->rotation_start_time = 0;
                                b->rotation_give_up = false;
                                pthread_mutex_unlock(&g_key_mutex);
                            } else {
                                initiate_key_rotation(b, &peer, -1, NULL, my_priv, peer_pub, profile_id, true);
                            }
                        }
                    }
                    usleep(500000);
                } else {
                    uint64_t now = get_time_ms_hs();
                    if (!b->rotation_give_up && (now - b->last_rotation_time > KEY_ROTATION_INTERVAL_MS + 15000)) {
                        if (!b->giveup_logged) {
                            fprintf(stderr, "[PQC-HS-L2] Key rotation timed out on Responder side (Policy %d). No HELLO received from Peer.\n", policy_id);
                            sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed. No handshake request received from Peer.");
                            b->giveup_logged = true;
                        }
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

                                    handle_handshake_success(b, derived_master, "Responder");

                                    forwarder_pre_diversify_pqc_keys(profile_id);
                                } else {
                                    fprintf(stderr, "[PQC-HS-L2] Handshake signature verification failed for Policy %d (Online state). Mismatched authentication keys or packet corrupted.\n", policy_id);
                                    sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake signature verification failed. Mismatched authentication keys.");
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
            uint64_t loop_now = get_time_ms_hs();
            bool keepalive_enabled;
            bool handshake_give_up;
            bool auto_retry_started = false;
            bool keepalive_timeout_recovery = false;
            bool flush_l3_queue = false;
            uint8_t keepalive_state = PQC_HS_STATE_FAILED;

            if (next_dispatcher_check_time == 0 ||
                loop_now >= next_dispatcher_check_time) {
                pqc_ensure_udp_dispatcher_running();
                next_dispatcher_check_time =
                    loop_now + PQC_HS_REQUEST_RETRY_MS;
            }

            pthread_mutex_lock(&g_key_mutex);
            if (b->keepalive_enabled && b->key_ready) {
                uint64_t monitor_from = b->last_keepalive_rx_time != 0
                    ? b->last_keepalive_rx_time
                    : b->keepalive_monitor_start_time;

                if (monitor_from != 0 && loop_now >= monitor_from &&
                    loop_now - monitor_from >=
                        PQC_HS_KEEPALIVE_TIMEOUT_MS) {
                    b->key_ready = false;
                    b->handshake_give_up = false;
                    b->handshake_start_time = 0;
                    b->rotation_give_up = false;
                    b->rotation_start_time = 0;
                    b->giveup_logged = false;
                    b->local_request_id = 0;
                    b->local_keepalive_seq = 0;
                    b->send_poke = !b->is_initiator;
                    b->last_keepalive_rx_time = 0;
                    b->keepalive_monitor_start_time = loop_now;
                    b->next_auto_retry_time = 0;
                    pqc_hs_clear_cache_locked(b);
                    keepalive_timeout_recovery = true;
                    flush_l3_queue = true;
                }
            }

            if (b->handshake_give_up) {
                if (b->next_auto_retry_time == 0) {
                    b->next_auto_retry_time =
                        loop_now + PQC_HS_AUTO_RETRY_INTERVAL_MS;
                } else if (loop_now >= b->next_auto_retry_time) {
                    b->handshake_give_up = false;
                    b->handshake_start_time = 0;
                    b->rotation_give_up = false;
                    b->rotation_start_time = 0;
                    b->giveup_logged = false;
                    b->local_request_id = 0;
                    b->local_keepalive_seq = 0;
                    b->send_poke = !b->is_initiator;
                    b->last_keepalive_rx_time = 0;
                    b->keepalive_monitor_start_time = loop_now;
                    b->next_auto_retry_time = 0;
                    pqc_hs_clear_cache_locked(b);
                    auto_retry_started = true;
                    flush_l3_queue = true;
                }
            }

            keepalive_enabled = b->keepalive_enabled;
            if (keepalive_enabled)
                keepalive_state = pqc_hs_l3_state_locked(b);
            handshake_give_up = b->handshake_give_up;
            pthread_mutex_unlock(&g_key_mutex);

            if (flush_l3_queue)
                pqc_flush_l3_rx_queue(b);
            if (keepalive_timeout_recovery) {
                fprintf(stderr,
                        "[PQC-HS-L3] Policy %d missed %d keepalive intervals; starting independent recovery as %s.\n",
                        policy_id, PQC_HS_KEEPALIVE_MISSED_LIMIT,
                        b->is_initiator ? "Initiator" : "Responder");
            }
            if (auto_retry_started) {
                fprintf(stderr,
                        "[PQC-HS-L3] Policy %d starting its scheduled automatic retry after %d seconds. Role=%s.\n",
                        policy_id,
                        PQC_HS_AUTO_RETRY_INTERVAL_MS / 1000,
                        b->is_initiator ? "Initiator" : "Responder");
            }

            if (keepalive_enabled && next_l3_keepalive_time == 0) {
                next_l3_keepalive_time =
                    loop_now + PQC_HS_KEEPALIVE_INTERVAL_MS;
                last_l3_keepalive_state = keepalive_state;
            } else if (keepalive_enabled &&
                       (keepalive_state != last_l3_keepalive_state ||
                        loop_now >= next_l3_keepalive_time)) {
                int keepalive_rc = pqc_hs_send_l3_keepalive(
                    b, sockfd, &peeraddr, my_priv);

                last_l3_keepalive_state = keepalive_state;
                next_l3_keepalive_time =
                    loop_now + PQC_HS_KEEPALIVE_INTERVAL_MS;
                if (keepalive_rc != 0 && keepalive_rc != -EAGAIN) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Failed to send signed KEM key keepalive for Policy %d: %s.\n",
                            policy_id, strerror(-keepalive_rc));
                }
            }

            if (handshake_give_up) {
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
                            size_t ifname_len =
                                strnlen(wan_ifname, IFNAMSIZ - 1);
                            memcpy(ifr.ifr_name, wan_ifname, ifname_len);
                            ifr.ifr_name[ifname_len] = '\0';
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
                            pthread_mutex_lock(&g_key_mutex);
                            b->is_initiator = is_initiator;
                            pthread_mutex_unlock(&g_key_mutex);
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

                    uint32_t session_id;
                    if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK ||
                        pqc_generate_session_id(&session_id) != 0) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Failed to create KEM/session material for Policy %d.\n",
                                policy_id);
                        usleep(500000);
                        continue;
                    }
                    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                    msg->magic = PQC_HS_MAGIC;
                    msg->msg_type = PQC_HS_MSG_HELLO;
                    msg->session_id = session_id;
                    msg->policy_id = (uint32_t)policy_id;
                    msg->sig_len = 0;
                    msg->data_len = (uint16_t)pk_sz;
                    memcpy(msg->payload, pk, (size_t)pk_sz);

                    pthread_mutex_lock(&g_key_mutex);
                    if (b->local_priv && b->local_priv[0] != '\0') {
                        free(my_priv);
                        my_priv = strdup(b->local_priv);
                    }
                    if (b->peer_pub && b->peer_pub[0] != '\0') {
                        free(peer_pub);
                        peer_pub = strdup(b->peer_pub);
                    }
                    pthread_mutex_unlock(&g_key_mutex);

                    size_t raw_priv_sz = 0;
                    uint8_t raw_priv[8192];
                    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
                    int sig_sz = 0;
                    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                                            msg->payload + pk_sz,
                                            &sig_sz) != TRF_PQC_OK) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Failed to sign HELLO for Policy %d.\n",
                                policy_id);
                        usleep(500000);
                        continue;
                    }
                    msg->sig_len = (uint16_t)sig_sz;

                    int retry_cnt = 0;
                    while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                        if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                            fprintf(stderr, "[PQC-HS-L3] Handshake timed out after %d seconds. Giving up on Policy %d.\n",
                                    PQC_HS_GIVEUP_TIMEOUT_MS / 1000, policy_id);
                            sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Peer connection timeout.");
                            b->handshake_give_up = true;
                            break;
                        }
                        fprintf(stderr,
                                "[PQC-WORKER-L3] Initiator Policy %d sending HELLO session %u (try: %d)...\n",
                                policy_id, session_id, retry_cnt + 1);
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
                                    resp->policy_id == (uint32_t)policy_id) {
                                    pthread_mutex_lock(&g_key_mutex);
                                    size_t raw_pub_sz = 0;
                                    uint8_t raw_pub[8192];
                                    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                                    pthread_mutex_unlock(&g_key_mutex);

                                    if (pqc_hs_verify_message(raw_pub, raw_pub_sz, resp) == TRF_PQC_OK) {
                                        if (trf_kem_decapsulate(sk, sk_sz, resp->payload, resp->data_len, ss) == TRF_PQC_OK) {
                                            uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                            derive_traffic_key(ss, 32, derived_master);

                                            handle_handshake_success(b, derived_master, "Initiator");

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
                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = get_time_ms_hs();
                    }
                    fprintf(stderr, "[PQC-WORKER-L3] Responder (Policy %d) listening for HELLO...\n", policy_id);
                    while (g_dispatcher_running && !b->key_ready && !b->thread_exit_sig) {
                        uint64_t now = get_time_ms_hs();
                        bool request_now;

                        if (now - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                            if (!b->giveup_logged) {
                                fprintf(stderr, "[PQC-HS-L3] Responder timed out waiting for HELLO on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake timeout. No HELLO received from Peer.");
                                b->giveup_logged = true;
                            }
                            b->handshake_give_up = true;
                            break;
                        }

                        pthread_mutex_lock(&g_key_mutex);
                        request_now = b->send_poke ||
                                      next_l3_request_time == 0 ||
                                      now >= next_l3_request_time;
                        b->send_poke = false;
                        pthread_mutex_unlock(&g_key_mutex);

                        if (request_now) {
                            int request_rc = pqc_hs_send_l3_handshake_request(
                                b, sockfd, &peeraddr, my_priv);

                            next_l3_request_time =
                                now + PQC_HS_REQUEST_RETRY_MS;
                            if (request_rc == 0) {
                                fprintf(stderr,
                                        "[PQC-HS-L3] Responder Policy %d sent authenticated handshake request to Initiator.\n",
                                        policy_id);
                            } else {
                                fprintf(stderr,
                                        "[PQC-HS-L3] Responder Policy %d failed to send authenticated handshake request: %s.\n",
                                        policy_id, strerror(-request_rc));
                            }
                        }

                        uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                        pqc_rx_pkt_info_t info;
                        int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                        if (rx_len > 0) {
                            const struct pqc_hs_msg *msg = NULL;
                            if (pqc_hs_validate_message(rx_buf, rx_len, &msg) == 0 &&
                                msg->magic == PQC_HS_MAGIC &&
                                msg->msg_type == PQC_HS_MSG_HELLO) {
                                pqc_hs_handle_l3_responder_hello(
                                    b, sockfd, &peeraddr, rx_buf, rx_len,
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
                        fprintf(stderr, "[PQC-HS-L3] Self-healing triggered (Initiator): active TX but no RX. Resetting key for Policy %d.\n", policy_id);
                        pthread_mutex_lock(&g_key_mutex);
                        b->key_ready = false;
                        b->last_sent_time = 0;
                        b->last_recv_time = 0;
                        pthread_mutex_unlock(&g_key_mutex);
                    } else if (now - b->last_rotation_time > L3_KEY_ROTATION_INTERVAL_MS) {
                        if (!b->rotation_give_up) {
                            if (b->rotation_start_time == 0) {
                                b->rotation_start_time = now;
                            }
                            if (now - b->rotation_start_time > 15000) {
                                fprintf(stderr, "[PQC-HS-L3] Key rotation timed out after 15 seconds. Giving up on Policy %d.\n", policy_id);
                                sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed.");
                                pthread_mutex_lock(&g_key_mutex);
                                b->key_ready = false;
                                b->handshake_give_up = true;
                                b->rotation_start_time = 0;
                                b->rotation_give_up = false;
                                pthread_mutex_unlock(&g_key_mutex);
                            } else {
                                initiate_l3_key_rotation(b, sockfd, &peeraddr,
                                                        my_priv, peer_pub,
                                                        profile_id);
                            }
                        }
                    }
                    usleep(500000);
                } else {
                    uint64_t now = get_time_ms_hs();
                    if (!b->rotation_give_up &&
                        (now - b->last_rotation_time > L3_KEY_ROTATION_INTERVAL_MS + 15000)) {
                        fprintf(stderr, "[PQC-HS-L3] Key rotation timed out on Responder side (Policy %d). No HELLO received from Peer.\n", policy_id);
                        sig_pqc_write_log(policy_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_ROTATION_FAILED, "Session key rotation failed. No handshake request received from Peer.");
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
                            msg->magic == PQC_HS_MAGIC &&
                            msg->msg_type == PQC_HS_MSG_HELLO) {
                            fprintf(stderr, "[PQC-HS-L3] Responder received HELLO while ONLINE. Peer might have restarted! Re-handshaking for Policy %d...\n", policy_id);
                            pqc_hs_handle_l3_responder_hello(
                                b, sockfd, &peeraddr, rx_buf, rx_len,
                                &my_priv, &peer_pub);
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
    pthread_mutex_lock(&g_key_mutex);
    b->thread_started = false;
    int binding_idx = (int)(b - g_policy_bindings);
    if (binding_idx >= 0 && binding_idx < MAX_POLICY_BINDINGS &&
        g_policy_bindings_active[binding_idx]) {
        /* A timed-out reload preserves the previous active binding.  Once its
         * old worker finally exits, allow the supervisor to restart it rather
         * than leaving this one policy permanently stopped. */
        b->thread_exit_sig = false;
    }
    pthread_mutex_unlock(&g_key_mutex);
    return NULL;
}

int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip) {
    int dispatcher_rc = pqc_ensure_udp_dispatcher_running();
    if (dispatcher_rc != 0 && dispatcher_rc != -EAGAIN) {
        fprintf(stderr,
                "[PQC-HS] UDP dispatcher is not ready for Profile %d: %s. Workers will keep retrying it.\n",
                profile_id, strerror(-dispatcher_rc));
    }

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
            pqc_start_policy_worker_locked(&g_policy_bindings[i]);
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
                         const char *peer_pub, bool is_tunnel) {
    uint64_t new_request_id = 0;
    char *deobf_peer = peer_pub ? strdup(peer_pub) : NULL;

    if (is_tunnel) {
        int request_id_rc = pqc_generate_request_id(&new_request_id);
        if (request_id_rc != 0) {
            fprintf(stderr,
                    "[PQC-BIND] Policy %d could not pre-generate an L3 handshake request ID: %s. Will retry in worker.\n",
                    policy_id, strerror(-request_id_rc));
        }
    }

    pthread_mutex_lock(&g_key_mutex);
    policy_key_binding_t *b = NULL;
    bool is_existing = false;
    bool binding_changed = false;
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
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
        b->local_request_id = 0;
        b->peer_request_id = 0;
        b->local_keepalive_seq = 0;
        b->peer_keepalive_epoch = 0;
        b->peer_keepalive_seq = 0;
        b->keepalive_monitor_start_time = 0;
        b->last_keepalive_rx_time = 0;
        b->next_auto_retry_time = 0;
        b->send_poke = false;
        b->keepalive_enabled = false;
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
            if (strcmp(b->key_id, key_id ? key_id : "") != 0) changed = true;
            if (b->is_tunnel != is_tunnel) changed = true;
            if (b->role_mode != role_mode) changed = true;

            if (changed) {
                binding_changed = true;
                fprintf(stderr, "[PQC-BIND-DBG] Policy %d: change detected, thread_started=%d, about to wait for worker exit...\n",
                        policy_id, (int)b->thread_started);
                if (b->thread_started) {
                    uint64_t wait_start = get_time_ms_hs();
                    b->thread_exit_sig = true;
                    int wait_iters = 0;
                    while (b->thread_started &&
                           get_time_ms_hs() - wait_start <
                               PQC_HS_WORKER_STOP_TIMEOUT_MS) {
                        pthread_mutex_unlock(&g_key_mutex);
                        usleep(1000);
                        pthread_mutex_lock(&g_key_mutex);
                        wait_iters++;
                        if (wait_iters % 500 == 0) {
                            fprintf(stderr, "[PQC-BIND-DBG] Policy %d: STILL waiting for worker exit... (%dms elapsed)\n",
                                    policy_id, (int)(get_time_ms_hs() - wait_start));
                        }
                    }
                    if (b->thread_started) {
                        int idx = (int)(b - g_policy_bindings);

                        fprintf(stderr,
                                "[PQC-BIND] Policy %d worker did not stop within %d ms; preserving its current binding so the remaining policies can continue loading.\n",
                                policy_id, PQC_HS_WORKER_STOP_TIMEOUT_MS);
                        if (idx >= 0 && idx < MAX_POLICY_BINDINGS)
                            g_policy_bindings_active[idx] = true;
                        pthread_mutex_unlock(&g_key_mutex);
                        free(deobf_peer);
                        return;
                    }
                    fprintf(stderr, "[PQC-BIND-DBG] Policy %d: worker exited after %dms. Proceeding.\n",
                            policy_id, (int)(get_time_ms_hs() - wait_start));
                    b->thread_exit_sig = false;
                }
                /* Also clears a stop request left by an earlier timed-out
                 * reload once that detached worker has finally exited. */
                b->thread_exit_sig = false;
                pqc_hs_clear_cache_locked(b);
                b->key_ready = false;
                b->handshake_give_up = false;
                b->handshake_start_time = 0;
                b->rotation_give_up = false;
                b->rotation_start_time = 0;
                b->send_poke = true;
                b->keepalive_enabled = false;
                b->keepalive_monitor_start_time = 0;
                b->last_keepalive_rx_time = 0;
                b->next_auto_retry_time = 0;
            }
        }
        b->policy_id = policy_id;
        b->profile_id = profile_id;
        b->role_mode = role_mode;
        // Default assignment for is_initiator based on static modes
        if (role_mode == PQC_ROLE_INITIATOR) {
            b->is_initiator = true;
        } else if (role_mode == PQC_ROLE_RESPONDER) {
            b->is_initiator = false;
        } else if (!is_existing || binding_changed) {
            b->is_initiator = false; // Will be resolved dynamically
        }
        if (is_tunnel && (!is_existing || binding_changed)) {
            b->local_request_id = new_request_id;
            b->peer_request_id = 0;
            b->local_keepalive_seq = 0;
            b->peer_keepalive_epoch = 0;
            b->peer_keepalive_seq = 0;
            b->keepalive_monitor_start_time = get_time_ms_hs();
            b->last_keepalive_rx_time = 0;
            b->next_auto_retry_time = 0;
            b->send_poke = role_mode != PQC_ROLE_INITIATOR;
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
        strncpy(b->key_id, key_id ? key_id : "", sizeof(b->key_id) - 1);
        b->key_id[sizeof(b->key_id) - 1] = '\0';
        b->is_tunnel = is_tunnel;
        if (is_tunnel) {
            /* Recovery monitoring starts as soon as -id binds the policy.
             * FAILED/HANDSHAKING status must also be advertised; otherwise a
             * freshly rebooted peer can never wake a READY peer. */
            b->keepalive_enabled = true;
            if (b->keepalive_monitor_start_time == 0)
                b->keepalive_monitor_start_time = get_time_ms_hs();
        }

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

    fprintf(stderr, "[PQC-VAULT-LOG] Fingerprint [%s]: Querying HashiCorp Vault directly...\n", clean_fg);

    // Query HashiCorp Vault directly — no RAM registry cache
    char priv_buf[8192] = "";
    char pub_buf[8192]  = "";
    if (sig_pqc_load_keys_from_vault(clean_fg, priv_buf, sizeof(priv_buf),
                                      pub_buf,  sizeof(pub_buf)) != 0) {
        fprintf(stderr, "[PQC-VAULT-LOG] ERROR: Fingerprint [%s] NOT found in HashiCorp Vault!\n", clean_fg);
        return -1;
    }

    if (out_priv) *out_priv = strdup(priv_buf);
    if (out_pub)  *out_pub  = strdup(pub_buf);
    return 0;
}

int sig_pqc_load_keys_from_vault(const char *target_fg,
                                  char *out_priv, size_t priv_sz,
                                  char *out_pub,  size_t pub_sz) {
    if (!target_fg || strlen(target_fg) == 0) return -1;
    char clean_fg[16] = "";
    strncpy(clean_fg, target_fg, 8);
    clean_fg[8] = '\0';

    char key_filename[64];
    snprintf(key_filename, sizeof(key_filename), "%s.key", clean_fg);

    // Try <fingerprint>.key first, then bare <fingerprint>
    int r_priv = sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PRIVATE, key_filename, out_priv, priv_sz);
    if (r_priv != 0)
        r_priv = sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PRIVATE, clean_fg, out_priv, priv_sz);

    int r_pub = sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PUBLIC, key_filename, out_pub, pub_sz);
    if (r_pub != 0)
        r_pub = sig_pqc_vault_read_key(VAULT_PATH_LOCAL_PUBLIC, clean_fg, out_pub, pub_sz);

    if (r_priv == 0 && r_pub == 0) {
        fprintf(stderr, "[PQC-VAULT-LOG] SUCCESS: Loaded local private key and public key for [%s] from HashiCorp Vault.\n", clean_fg);
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
                fprintf(stderr, "[PQC-RECONCILE] Policy %d PQC binding is no longer active. Deactivating and clearing keys.\n", b->policy_id);
                if (b->thread_started) {
                    uint64_t wait_start = get_time_ms_hs();
                    b->thread_exit_sig = true;
                    while (b->thread_started &&
                           get_time_ms_hs() - wait_start <
                               PQC_HS_WORKER_STOP_TIMEOUT_MS) {
                        pthread_mutex_unlock(&g_key_mutex);
                        usleep(1000);
                        pthread_mutex_lock(&g_key_mutex);
                    }
                    if (b->thread_started) {
                        fprintf(stderr,
                                "[PQC-RECONCILE] Policy %d worker stop timed out after %d ms; deferring only this policy cleanup.\n",
                                b->policy_id,
                                PQC_HS_WORKER_STOP_TIMEOUT_MS);
                        continue;
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
            b->keepalive_enabled = false;
            b->local_request_id = 0;
            b->peer_request_id = 0;
            b->local_keepalive_seq = 0;
            b->peer_keepalive_epoch = 0;
            b->peer_keepalive_seq = 0;
            b->keepalive_monitor_start_time = 0;
            b->last_keepalive_rx_time = 0;
            b->next_auto_retry_time = 0;
            pqc_hs_clear_cache_locked(b);
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
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
    uint64_t new_request_id = 0;
    int request_id_rc = pqc_generate_request_id(&new_request_id);
    int profile_id = -1;

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings[i].policy_id == policy_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->rotation_give_up = false;
            b->rotation_start_time = 0;
            b->key_ready = false;
            profile_id = b->profile_id;
            if (b->is_tunnel) {
                b->giveup_logged = false;
                b->keepalive_enabled = true;
                b->local_request_id =
                    request_id_rc == 0 ? new_request_id : 0;
                b->local_keepalive_seq = 0;
                b->last_keepalive_rx_time = 0;
                b->keepalive_monitor_start_time = get_time_ms_hs();
                b->next_auto_retry_time = 0;
                b->send_poke = !b->is_initiator;
                pqc_hs_clear_cache_locked(b);
                pqc_flush_l3_rx_queue(b);
            } else {
                b->send_poke = true;
            }
            fprintf(stderr, "[PQC-HS] Manual retry triggered for Policy %d. All retry states reset.\n", policy_id);
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    if (profile_id >= 0)
        sig_pqc_handshake_start(profile_id, "", "");
}

int sig_pqc_trigger_retry_with_info(int policy_id, char *out_info, size_t out_max) {
    bool found = false;
    uint64_t new_request_id = 0;
    int request_id_rc = pqc_generate_request_id(&new_request_id);
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
            if (b->is_tunnel) {
                b->giveup_logged = false;
                b->keepalive_enabled = true;
                b->local_request_id =
                    request_id_rc == 0 ? new_request_id : 0;
                b->local_keepalive_seq = 0;
                b->last_keepalive_rx_time = 0;
                b->keepalive_monitor_start_time = get_time_ms_hs();
                b->next_auto_retry_time = 0;
                b->send_poke = !b->is_initiator;
                pqc_hs_clear_cache_locked(b);
                pqc_flush_l3_rx_queue(b);
            } else {
                b->send_poke = true;
            }
            
            target_binding = *b;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (found) {
        sig_pqc_handshake_start(target_binding.profile_id, "", "");
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
    fprintf(stderr, "[DB-PQC-DBG] ENTER load_and_bind_policy: policy=%d profile=%d conn_status=%s\n",
            db_policy_id, profile_id,
            conn ? PQstatus(conn) == CONNECTION_OK ? "OK" : "BAD" : "NULL");

    char peer_ip[64] = "0.0.0.0";
    char wan_ifname_buf[64] = "";
    const char *wan_ifname = "";
    bool is_tunnel = false;

    char policy_id_str[32];
    snprintf(policy_id_str, sizeof(policy_id_str), "%d", db_policy_id);
    const char *pqc_params[1] = { policy_id_str };

    // Query to get the tunnel parameters from pqc_exchange_tunnels
    // Use db_policy_id -> JOIN ne_policies to map profile correctly
    PGresult *tunnel_res = PQexecParams(conn,
        "SELECT t.tunnel_name, t.tunnel_ip::text, t.peer_tunnel_ip::text "
        "FROM pqc_exchange_tunnels t "
        "JOIN profile_tunnel_ref r ON t.id = r.tunnel_id "
        "JOIN ne_policies p ON r.profile_id = p.profile_id "
        "WHERE p.id = $1",
        1, NULL, pqc_params, NULL, NULL, 0);
    fprintf(stderr, "[DB-PQC-DBG] policy=%d tunnel query status=%s ntuples=%d err='%s'\n",
            db_policy_id, PQresStatus(PQresultStatus(tunnel_res)),
            PQntuples(tunnel_res), PQresultErrorMessage(tunnel_res));

    if (PQresultStatus(tunnel_res) == PGRES_TUPLES_OK && PQntuples(tunnel_res) > 0) {
        is_tunnel = true;
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

        char peer_fg_buf[16] = "";
        char *deobf_pub = NULL;
        bool valid = true;

        // Query peer public key 100% directly from HashiCorp Vault (kv/PQC_Key/remote_public/<peer_pub>)
        char vault_peer_pub_buf[8192] = "";
        if (peer_pub_path && strlen(peer_pub_path) > 0 &&
            sig_pqc_vault_read_key(VAULT_PATH_REMOTE_PUBLIC, peer_pub_path, vault_peer_pub_buf, sizeof(vault_peer_pub_buf)) == 0) {
            fprintf(stderr, "[PQC-VAULT-LOG] SUCCESS: Loaded peer public key [%s] 100%% from HashiCorp Vault (remote_public).\n", peer_pub_path);
            deobf_pub = strdup(vault_peer_pub_buf);
            strncpy(peer_fg_buf, peer_pub_path, 8);
            peer_fg_buf[8] = '\0';
        } else {
            fprintf(stderr, "[DB-PQC] ERROR: Policy %d peer_pub key [%s] NOT found in HashiCorp Vault (remote_public)!\n",
                    db_policy_id, peer_pub_path ? peer_pub_path : "N/A");
            valid = false;
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
            fprintf(stderr, "[DB-PQC-DBG] CALLING sig_pqc_bind_policy for policy=%d...\n", db_policy_id);
            sig_pqc_bind_policy(db_policy_id, profile_id, role_mode, peer_ip, local_fg, peer_fg_buf, wan_ifname, key_id, found_priv, found_pub, deobf_pub, is_tunnel);
            fprintf(stderr, "[DB-PQC-DBG] sig_pqc_bind_policy RETURNED for policy=%d\n", db_policy_id);
        } else {
            fprintf(stderr, "[DB-PQC] ERROR: Policy %d PQC config is invalid or keys are missing. PQC Handshake will NOT start.\n", db_policy_id);
            sig_pqc_write_log(db_policy_id, key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Security configuration error.");
        }
        // sig_pqc_find_identity returns strdup'd buffers — free them after use
        if (found_priv) { free(found_priv); found_priv = NULL; }
        if (found_pub)  { free(found_pub);  found_pub  = NULL; }
        if (deobf_pub) free(deobf_pub);
    } else {
        fprintf(stderr, "[DB-PQC] ERROR: No policy identity configuration found in pqc_identities for PQC policy %d. PQC Handshake will NOT start.\n", db_policy_id);
        sig_pqc_write_log(db_policy_id, "", PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Security configuration error.");
    }
    PQclear(peer_res);
}
