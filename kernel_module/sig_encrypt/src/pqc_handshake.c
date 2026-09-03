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
#include <stdatomic.h>
#include <time.h>
#include <endian.h>
#include <limits.h>

#define PQC_RX_PKT_MAX     10000
#define KEY_ROTATION_INTERVAL_MS 3000000
#define PQC_HS_GIVEUP_TIMEOUT_MS 15000
#define PQC_WORKER_STOP_TIMEOUT_MS 3000
#define PQC_HS_REQUEST_RETRY_MS 1000
#define PQC_HS_REQUEST_DATA_SZ ((uint16_t)sizeof(uint64_t))
#define PQC_HS_KEEPALIVE_INTERVAL_MS 15000
#define PQC_HS_KEEPALIVE_MISSED_LIMIT 3
#define PQC_HS_KEEPALIVE_TIMEOUT_MS \
    (PQC_HS_KEEPALIVE_INTERVAL_MS * PQC_HS_KEEPALIVE_MISSED_LIMIT)
#define PQC_HS_AUTO_RETRY_INTERVAL_MS 15000
#define PQC_HS_KEY_FINGERPRINT_SZ 32
#define PQC_HS_STATE_READY 1
#define PQC_HS_STATE_FAILED 2
#define PQC_HS_STATE_HANDSHAKING 3
#define PQC_HS_INIT_WIRE_VERSION 1
#define PQC_HS_INIT_HAS_CURRENT 0x01
#define PQC_HS_INIT_HAS_PREVIOUS 0x02

enum pqc_hs_hello_diag_status {
    PQC_HS_HELLO_DIAG_OK = 0,
    PQC_HS_HELLO_DIAG_MALFORMED,
    PQC_HS_HELLO_DIAG_FINGERPRINT,
    PQC_HS_HELLO_DIAG_SESSION_CONFLICT,
    PQC_HS_HELLO_DIAG_MISSING_KEYS,
    PQC_HS_HELLO_DIAG_BAD_SIGNATURE,
    PQC_HS_HELLO_DIAG_ENCAPSULATE,
    PQC_HS_HELLO_DIAG_SIGN_RESPONSE,
    PQC_HS_HELLO_DIAG_SEND_RESPONSE,
};

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

#pragma pack(push, 1)
typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t current_key_id;
    uint8_t previous_key_id;
} pqc_hs_init_hello_wire_t;

typedef struct {
    uint8_t version;
    uint8_t agreed_key_id;
    uint8_t key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
} pqc_hs_init_resp_wire_t;
#pragma pack(pop)

#define PQC_HS_KEEPALIVE_DATA_SZ \
    ((uint16_t)sizeof(pqc_hs_keepalive_wire_t))

/* TEST ONLY: allow the two peers to use different local profile IDs.
 * Set this back to 0 after the profile-mismatch test. */
#define PQC_TEST_ALLOW_PROFILE_MISMATCH 1

extern void sig_pqc_on_key_ready(int profile_id, const uint8_t *key_bytes,
                                 uint64_t config_generation);
extern void sig_pqc_on_key_activated(int profile_id,
                                     const uint8_t *key_bytes,
                                     uint64_t config_generation);

#pragma pack(push, 1)
typedef struct {
    uint8_t epoch_be[sizeof(uint64_t)];
    uint8_t key_id;
    uint8_t key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
} pqc_rekey_wire_t;
#pragma pack(pop)

#define PQC_REKEY_WIRE_SIZE ((uint16_t)sizeof(pqc_rekey_wire_t))

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

static atomic_bool g_dispatcher_running = ATOMIC_VAR_INIT(false);
static pqc_runtime_state_t g_dispatcher_state = PQC_RUNTIME_STOPPED;
static int g_dispatcher_last_error;
static pthread_cond_t g_dispatcher_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_worker_state_cond = PTHREAD_COND_INITIALIZER;

static int pqc_policy_rx_recv(policy_key_binding_t *b, uint8_t *buf, int buf_sz, pqc_rx_pkt_info_t *info, int timeout_ms);
static void *pqc_udp_dispatcher_thread(void *arg);

static bool pqc_dispatcher_is_running(void) {
    return atomic_load_explicit(&g_dispatcher_running,
                                memory_order_acquire);
}

static const char *pqc_runtime_state_name(pqc_runtime_state_t state) {
    switch (state) {
    case PQC_RUNTIME_STOPPED:
        return "STOPPED";
    case PQC_RUNTIME_STARTING:
        return "STARTING";
    case PQC_RUNTIME_RUNNING:
        return "RUNNING";
    case PQC_RUNTIME_FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

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

/* These diagnostic slots are owned by one profile.  Returning true only on
 * a transition keeps persistent packet/retry errors from flooding journald. */
static bool pqc_hs_diag_changed(int *last_status, int new_status) {
    if (!last_status || *last_status == new_status)
        return false;
    *last_status = new_status;
    return true;
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

/* g_key_mutex must be held so the peer public key and role cannot be
 * replaced while an incoming restart request is authenticated. */
static int pqc_hs_verify_request_locked(policy_key_binding_t *b,
                                        const struct pqc_hs_msg *msg,
                                        uint64_t *request_id) {
    uint8_t raw_pub[8192];
    uint64_t request_id_be;
    size_t raw_pub_sz = 0;

    if (!b || !msg || !request_id ||
        msg->magic != PQC_HS_MAGIC || msg->msg_type != PQC_HS_MSG_POKE ||
        msg->session_id == 0 ||
        !pqc_hs_profile_matches(msg->profile_id, b->profile_id) ||
        msg->data_len != PQC_HS_REQUEST_DATA_SZ || msg->sig_len == 0 ||
        !b->is_initiator || !b->peer_pub || b->peer_pub[0] == '\0')
        return -EINVAL;

    trf_base64_decode(b->peer_pub, raw_pub, &raw_pub_sz);
    if (raw_pub_sz == 0 ||
        pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK)
        return -EKEYREJECTED;

    memcpy(&request_id_be, msg->payload, sizeof(request_id_be));
    *request_id = be64toh(request_id_be);
    return *request_id ? 0 : -EINVAL;
}

static int pqc_hs_send_handshake_request(policy_key_binding_t *b,
                                         int sockfd,
                                         const struct sockaddr_in *peeraddr,
                                         const char *my_priv) {
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
    request->profile_id = (uint32_t)b->profile_id;
    request->data_len = PQC_HS_REQUEST_DATA_SZ;
    if (pqc_generate_session_id(&request->session_id) != 0)
        return errno ? -errno : -EIO;

    request_id_be = htobe64(request_id);
    memcpy(request->payload, &request_id_be, sizeof(request_id_be));
    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
    if (raw_priv_sz == 0 ||
        pqc_hs_sign_message(raw_priv, raw_priv_sz, request,
                            request->payload + request->data_len,
                            &sig_sz) != TRF_PQC_OK || sig_sz <= 0 ||
        (size_t)sig_sz > UINT16_MAX)
        return -EKEYREJECTED;

    request_len = sizeof(*request) + request->data_len + (size_t)sig_sz;
    if (request_len > sizeof(request_buf))
        return -EMSGSIZE;
    request->sig_len = (uint16_t)sig_sz;

    sent = sendto(sockfd, request, request_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    if (sent != (ssize_t)request_len)
        return sent < 0 ? -errno : -EIO;
    return 0;
}

/* g_key_mutex must be held while reading handshake/key state. */
static uint8_t pqc_hs_l3_state_locked(const policy_key_binding_t *b) {
    if ((!b->handshake_give_up && b->handshake_start_time != 0 &&
         !b->key_ready) || pqc_key_rotation_in_progress(&b->rotation))
        return PQC_HS_STATE_HANDSHAKING;
    if (b->key_ready && b->key_slots_valid[KEY_SLOT_CURRENT])
        return PQC_HS_STATE_READY;
    return PQC_HS_STATE_FAILED;
}

static int pqc_hs_l3_key_fingerprint_locked(
    const policy_key_binding_t *b,
    uint8_t fingerprint[PQC_HS_KEY_FINGERPRINT_SZ]) {
    if (!b || !fingerprint ||
        pqc_hs_l3_state_locked(b) != PQC_HS_STATE_READY)
        return -EINVAL;

    return trf_calculate_digest(DIGEST_TYPE_SHA256,
                                b->keys[KEY_SLOT_CURRENT],
                                PQC_TRAFFIC_KEY_SZ,
                                fingerprint) == TRF_PQC_OK ? 0 : -EIO;
}

/* g_key_mutex must be held while authenticating the peer identity and
 * comparing the peer role/profile with the active binding. */
static int pqc_hs_verify_l3_keepalive_locked(
    policy_key_binding_t *b, const struct pqc_hs_msg *msg,
    pqc_hs_keepalive_status_t *status) {
    const pqc_hs_keepalive_wire_t *wire;
    uint8_t raw_pub[8192];
    uint64_t epoch_be;
    uint64_t sequence_be;
    size_t raw_pub_sz = 0;
    bool fingerprint_is_zero = true;

    if (!b || !msg || !status || !b->is_tunnel ||
        msg->magic != PQC_HS_MAGIC ||
        msg->msg_type != PQC_HS_MSG_KEEPALIVE ||
        msg->session_id == 0 ||
        !pqc_hs_profile_matches(msg->profile_id, b->profile_id) ||
        msg->data_len != PQC_HS_KEEPALIVE_DATA_SZ || msg->sig_len == 0 ||
        !b->peer_pub || b->peer_pub[0] == '\0')
        return -EINVAL;

    trf_base64_decode(b->peer_pub, raw_pub, &raw_pub_sz);
    if (raw_pub_sz == 0 ||
        pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK)
        return -EKEYREJECTED;

    wire = (const pqc_hs_keepalive_wire_t *)msg->payload;
    if ((wire->state != PQC_HS_STATE_READY &&
         wire->state != PQC_HS_STATE_FAILED &&
         wire->state != PQC_HS_STATE_HANDSHAKING) ||
        wire->role > 1 || wire->role == (uint8_t)b->is_initiator)
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
        memcpy(key_material, b->keys[KEY_SLOT_CURRENT],
               sizeof(key_material));
    } else {
        memset(key_material, 0, sizeof(key_material));
    }
    pthread_mutex_unlock(&g_key_mutex);

    memset(keepalive_buf, 0, sizeof(keepalive_buf));
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_KEEPALIVE;
    msg->profile_id = (uint32_t)b->profile_id;
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

static void pqc_flush_rx_queue(policy_key_binding_t *b) {
    if (!b) return;

    pthread_mutex_lock(&b->rx_mutex);
    for (int i = 0; i < PQC_RX_QUEUE_SIZE; i++) {
        free(b->rx_queue[i]);
        b->rx_queue[i] = NULL;
        b->rx_len[i] = 0;
        memset(&b->rx_info[i], 0, sizeof(b->rx_info[i]));
    }
    b->rx_head = 0;
    b->rx_tail = 0;
    pthread_cond_broadcast(&b->rx_cond);
    pthread_mutex_unlock(&b->rx_mutex);
}

/* g_key_mutex must be held.  Recovery is deliberately local to one binding:
 * no other profile loses its key, queue, retry state, or worker.  The kernel
 * keeps its current/previous datapath key slots until a successful handshake
 * invokes sig_pqc_on_key_ready() with a replacement key. */
static void pqc_hs_begin_profile_recovery_locked(policy_key_binding_t *b,
                                                  uint64_t now) {
    if (!b)
        return;

    b->key_ready = false;
    b->handshake_give_up = false;
    b->handshake_start_time = 0;
    b->local_request_id = 0;
    b->local_keepalive_seq = 0;
    b->send_poke = !b->is_initiator;
    b->keepalive_enabled = b->is_tunnel;
    b->last_keepalive_rx_time = 0;
    b->keepalive_monitor_start_time = now;
    b->next_auto_retry_time = 0;
    pqc_hs_clear_cache_locked(b);
}

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

static bool pqc_hs_key_id_reserved(uint8_t candidate,
                                   uint8_t local_current,
                                   uint8_t local_previous,
                                   uint8_t peer_current,
                                   uint8_t peer_previous)
{
    return candidate == 0 || candidate == local_current ||
           candidate == local_previous || candidate == peer_current ||
           candidate == peer_previous;
}

/* Select one ID from the derived key fingerprint, while excluding every ID
 * that either peer still associates with CURRENT or PREVIOUS.  The responder
 * signs this decision and the initiator must install the exact same ID. */
static uint8_t pqc_hs_choose_agreed_key_id(
    const policy_key_binding_t *b,
    const pqc_hs_init_hello_wire_t *peer_state,
    const uint8_t key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ])
{
    uint8_t local_current = 0;
    uint8_t local_previous = 0;
    uint8_t peer_current = 0;
    uint8_t peer_previous = 0;

    if (!b || !peer_state || !key_fingerprint)
        return 0;
    if (b->key_slots_valid[KEY_SLOT_CURRENT])
        local_current = b->key_ids[KEY_SLOT_CURRENT];
    if (b->key_slots_valid[KEY_SLOT_PREV])
        local_previous = b->key_ids[KEY_SLOT_PREV];
    if (peer_state->flags & PQC_HS_INIT_HAS_CURRENT)
        peer_current = peer_state->current_key_id;
    if (peer_state->flags & PQC_HS_INIT_HAS_PREVIOUS)
        peer_previous = peer_state->previous_key_id;

    for (size_t i = 0; i < PQC_HS_KEY_FINGERPRINT_SZ; i++) {
        uint8_t candidate = key_fingerprint[i];

        if (!pqc_hs_key_id_reserved(candidate, local_current,
                                    local_previous, peer_current,
                                    peer_previous))
            return candidate;
    }
    for (unsigned int i = 1; i <= UINT8_MAX; i++) {
        uint8_t candidate = (uint8_t)i;

        if (!pqc_hs_key_id_reserved(candidate, local_current,
                                    local_previous, peer_current,
                                    peer_previous))
            return candidate;
    }
    return 0;
}

static uint64_t get_time_ms_hs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void handle_handshake_success(policy_key_binding_t *b,
                                     const uint8_t *derived_master,
                                     uint8_t agreed_key_id,
                                     const char *role) {
    uint64_t now = get_time_ms_hs();

    if (b->key_ready) {
        sig_pqc_write_log(b->profile_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Session key updated.");
    } else {
        sig_pqc_write_log(b->profile_id, b->key_id, PQC_LOG_LEVEL_INFO, PQC_LOG_STATUS_SUCCESS, "Secure session established.");
    }

    memcpy(b->keys[KEY_SLOT_PREV], b->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    b->key_ids[KEY_SLOT_PREV] = b->key_ids[KEY_SLOT_CURRENT];
    b->key_slots_valid[KEY_SLOT_PREV] = b->key_slots_valid[KEY_SLOT_CURRENT];

    memcpy(b->keys[KEY_SLOT_CURRENT], derived_master, PQC_TRAFFIC_KEY_SZ);
    b->key_ids[KEY_SLOT_CURRENT] = agreed_key_id;
    b->key_slots_valid[KEY_SLOT_CURRENT] = true;

    b->key_slots_valid[KEY_SLOT_NEXT] = false;

    memcpy(b->encrypt_key, derived_master, PQC_TRAFFIC_KEY_SZ);
    memcpy(b->decrypt_key, derived_master, PQC_TRAFFIC_KEY_SZ);

    b->key_ready = true;
    b->last_sent_time = now;
    b->last_recv_time = now;
    b->last_rotation_time = now;
    b->handshake_start_time = 0;
    b->handshake_give_up = false;
    pqc_key_rotation_init(&b->rotation);
    if (b->is_tunnel) {
        b->keepalive_enabled = true;
        b->keepalive_peer_unreachable = false;
        b->keepalive_monitor_start_time = now;
        b->last_keepalive_rx_time = 0;
        b->next_auto_retry_time = 0;
    }

    int idx = b - g_policy_bindings;
    if (idx >= 0 && idx < MAX_POLICY_BINDINGS) {
        g_policy_key_version[idx]++;
    }

    fprintf(stderr,
            "[PQC-HS] %s Handshake SUCCESS for Profile %d. Promoted new key ID: %d to CURRENT. Key prefix: %02X%02X%02X%02X...\n",
            role, b->profile_id, b->key_ids[KEY_SLOT_CURRENT],
            derived_master[0], derived_master[1], derived_master[2],
            derived_master[3]);

}

static int pqc_hs_send_cached_response(policy_key_binding_t *b, int cache_slot,
                                       uint32_t session_id, const uint8_t hello_hash[32],
                                       int sockfd, const struct sockaddr_in *peeraddr,
                                       bool replay) {
    uint8_t *response = NULL;
    uint8_t master_key[PQC_TRAFFIC_KEY_SZ];
    int response_len = 0;
    uint8_t agreed_key_id = 0;
    bool already_promoted = false;
    bool is_rekey = false;
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
        agreed_key_id = b->hs_cache[cache_slot].agreed_key_id;
        already_promoted = b->hs_cache[cache_slot].key_promoted;
        is_rekey = b->hs_cache[cache_slot].is_rekey;
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (!response) return -1;

    sent = sendto(sockfd, response, (size_t)response_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    free(response);
    if (sent != response_len) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_SEND_RESPONSE)) {
            fprintf(stderr,
                    "[PQC-HS-L3] Failed to send RESP for Profile %d, session %u: %s\n",
                    b->profile_id, session_id,
                    sent < 0 ? strerror(errno) : "short UDP send");
        }
        return -1;
    }

    if (!is_rekey && !already_promoted) {
        pthread_mutex_lock(&g_key_mutex);
        if (b->hs_cache[cache_slot].valid &&
            b->hs_cache[cache_slot].session_id == session_id &&
            memcmp(b->hs_cache[cache_slot].hello_hash, hello_hash, 32) == 0 &&
            !b->hs_cache[cache_slot].key_promoted) {
            b->hs_cache[cache_slot].key_promoted = true;
            handle_handshake_success(b, master_key, agreed_key_id,
                                     "Responder");
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

    /* A cached RESP can be retransmitted several times for the same HELLO.
     * That is normal retry traffic, not a state change, so keep it silent. */
    if (!replay) {
        fprintf(stderr,
                "[PQC-HS-L3] Responder sent new RESP for Profile %d, session %u.\n",
                b->profile_id, session_id);
    }
    b->hello_rx_last_status = PQC_HS_HELLO_DIAG_OK;
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
    bool is_rekey;
    pqc_hs_init_hello_wire_t peer_init_state = {0};
    const uint8_t *kem_public_key;
    size_t kem_public_key_len;
    uint8_t init_key_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ] = {0};
    uint8_t init_agreed_key_id = 0;
    uint8_t rekey_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ] = {0};
    uint8_t rekey_id = 0;
    size_t response_prefix = 0;
    char *new_my_priv = NULL;
    char *new_peer_pub = NULL;

    if (pqc_hs_validate_message(rx_buf, rx_len, &msg) != 0 ||
        msg->magic != PQC_HS_MAGIC ||
        (msg->msg_type != PQC_HS_MSG_HELLO &&
         msg->msg_type != PQC_HS_MSG_REKEY_HELLO) ||
        !pqc_hs_profile_matches(msg->profile_id, b->profile_id) ||
        msg->session_id == 0) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_MALFORMED)) {
            fprintf(stderr, "[PQC-HS-L3] Rejected malformed/mismatched HELLO for Profile %d.\n",
                    b->profile_id);
        }
        return -1;
    }
    is_rekey = msg->msg_type == PQC_HS_MSG_REKEY_HELLO;
    if (is_rekey && !b->l2_rekey_enabled)
        return -EOPNOTSUPP;
    if (!is_rekey) {
        if (msg->data_len <= sizeof(peer_init_state)) {
            if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                    PQC_HS_HELLO_DIAG_MALFORMED))
                fprintf(stderr,
                        "[PQC-HS-L3] Rejected legacy/malformed INIT HELLO for Profile %d.\n",
                        b->profile_id);
            return -EPROTO;
        }
        memcpy(&peer_init_state, msg->payload, sizeof(peer_init_state));
        if (peer_init_state.version != PQC_HS_INIT_WIRE_VERSION ||
            (peer_init_state.flags &
             ~(PQC_HS_INIT_HAS_CURRENT | PQC_HS_INIT_HAS_PREVIOUS)) ||
            ((peer_init_state.flags & PQC_HS_INIT_HAS_CURRENT) != 0) !=
                (peer_init_state.current_key_id != 0) ||
            ((peer_init_state.flags & PQC_HS_INIT_HAS_PREVIOUS) != 0) !=
                (peer_init_state.previous_key_id != 0) ||
            (peer_init_state.current_key_id != 0 &&
             peer_init_state.current_key_id ==
                 peer_init_state.previous_key_id)) {
            if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                    PQC_HS_HELLO_DIAG_MALFORMED))
                fprintf(stderr,
                        "[PQC-HS-L3] Rejected invalid INIT key metadata for Profile %d.\n",
                        b->profile_id);
            return -EPROTO;
        }
        kem_public_key = msg->payload + sizeof(peer_init_state);
        kem_public_key_len = msg->data_len - sizeof(peer_init_state);
    } else {
        kem_public_key = msg->payload;
        kem_public_key_len = msg->data_len;
    }

    if (trf_calculate_digest(DIGEST_TYPE_SHA256, rx_buf, rx_len, hello_hash) != TRF_PQC_OK) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_FINGERPRINT)) {
            fprintf(stderr, "[PQC-HS-L3] Failed to fingerprint HELLO for Profile %d.\n",
                    b->profile_id);
        }
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
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_SESSION_CONFLICT)) {
            fprintf(stderr,
                    "[PQC-HS-L3] Rejected HELLO reusing session %u with different content for Profile %d.\n",
                    msg->session_id, b->profile_id);
        }
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
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_MISSING_KEYS)) {
            fprintf(stderr, "[PQC-HS-L3] Missing responder authentication keys for Profile %d.\n",
                    b->profile_id);
        }
        return -1;
    }
    free(*my_priv);
    free(*peer_pub);
    *my_priv = new_my_priv;
    *peer_pub = new_peer_pub;

    trf_base64_decode(*peer_pub, raw_pub, &raw_pub_sz);
    if (pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_BAD_SIGNATURE)) {
            fprintf(stderr,
                    "[PQC-HS-L3] HELLO signature verification failed for Profile %d, session %u.\n",
                    b->profile_id, msg->session_id);
            sig_pqc_write_log(b->profile_id, b->key_id,
                              PQC_LOG_LEVEL_ERROR,
                              PQC_LOG_STATUS_FAILED,
                              "Handshake signature verification failed. Mismatched authentication keys.");
        }
        return -1;
    }

    if (trf_kem_encapsulate(kem_public_key, (int)kem_public_key_len,
                            ct, &ct_sz, ss) != TRF_PQC_OK) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_ENCAPSULATE)) {
            fprintf(stderr, "[PQC-HS-L3] KEM encapsulation failed for Profile %d, session %u.\n",
                    b->profile_id, msg->session_id);
        }
        return -1;
    }

    derive_traffic_key(ss, 32, derived_master);
    if (is_rekey) {
        if (!b->key_ready ||
            trf_calculate_digest(DIGEST_TYPE_SHA256, derived_master,
                                 sizeof(derived_master),
                                 rekey_fingerprint) != TRF_PQC_OK)
            return -1;
        rekey_id = pqc_key_rotation_choose_id(
            b->key_ids[KEY_SLOT_CURRENT],
            b->key_slots_valid[KEY_SLOT_PREV] ?
                b->key_ids[KEY_SLOT_PREV] : 0,
            rekey_fingerprint);
        if (!rekey_id)
            return -1;
        response_prefix = sizeof(pqc_rekey_wire_t);
    } else {
        if (trf_calculate_digest(DIGEST_TYPE_SHA256, derived_master,
                                 sizeof(derived_master),
                                 init_key_fingerprint) != TRF_PQC_OK)
            return -EIO;
        pthread_mutex_lock(&g_key_mutex);
        init_agreed_key_id = pqc_hs_choose_agreed_key_id(
            b, &peer_init_state, init_key_fingerprint);
        pthread_mutex_unlock(&g_key_mutex);
        if (!init_agreed_key_id)
            return -ENOSPC;
        response_prefix = sizeof(pqc_hs_init_resp_wire_t);
    }

    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)response_buf;
    resp->magic = PQC_HS_MAGIC;
    resp->msg_type = is_rekey ? PQC_HS_MSG_REKEY_RESP : PQC_HS_MSG_RESP;
    resp->session_id = msg->session_id;
    resp->profile_id = (uint32_t)b->profile_id;
    resp->data_len = (uint16_t)(response_prefix + (size_t)ct_sz);
    if (is_rekey) {
        pqc_rekey_wire_t *wire = (pqc_rekey_wire_t *)resp->payload;
        uint64_t epoch_be = htobe64((uint64_t)msg->session_id);

        memcpy(wire->epoch_be, &epoch_be, sizeof(epoch_be));
        wire->key_id = rekey_id;
        memcpy(wire->key_fingerprint, rekey_fingerprint,
               sizeof(wire->key_fingerprint));
    } else {
        pqc_hs_init_resp_wire_t *wire =
            (pqc_hs_init_resp_wire_t *)resp->payload;

        wire->version = PQC_HS_INIT_WIRE_VERSION;
        wire->agreed_key_id = init_agreed_key_id;
        memcpy(wire->key_fingerprint, init_key_fingerprint,
               sizeof(wire->key_fingerprint));
    }
    memcpy(resp->payload + response_prefix, ct, (size_t)ct_sz);

    trf_base64_decode(*my_priv, raw_priv, &raw_priv_sz);
    if (pqc_hs_sign_message(raw_priv, raw_priv_sz, resp,
                            resp->payload + resp->data_len,
                            &sig_sz) != TRF_PQC_OK) {
        if (pqc_hs_diag_changed(&b->hello_rx_last_status,
                                PQC_HS_HELLO_DIAG_SIGN_RESPONSE)) {
            fprintf(stderr, "[PQC-HS-L3] Failed to sign RESP for Profile %d, session %u.\n",
                    b->profile_id, msg->session_id);
        }
        return -1;
    }
    resp->sig_len = (uint16_t)sig_sz;
    response_len = (int)sizeof(*resp) + resp->data_len + sig_sz;
    if (response_len > PQC_HS_MSG_MAX_SZ) return -1;

    uint8_t *response_copy = malloc((size_t)response_len);
    if (!response_copy) return -1;
    memcpy(response_copy, response_buf, (size_t)response_len);

    /* Build and sign the complete response before staging NEXT.  A signing
     * or allocation error must never leave a responder-side NEXT key that
     * the peer could not possibly commit. */
    if (is_rekey) {
        int stage_rc;

        pthread_mutex_lock(&g_key_mutex);
        stage_rc = pqc_key_rotation_stage(
            &b->rotation, b->profile_id, (uint64_t)msg->session_id,
            rekey_id, derived_master, rekey_fingerprint, b->keys,
            b->key_ids, b->key_slots_valid, get_time_ms_hs());
        pthread_mutex_unlock(&g_key_mutex);
        if (stage_rc != 0) {
            free(response_copy);
            fprintf(stderr,
                    "[PQC-REKEY] Profile %d responder could not stage NEXT: %s.\n",
                    b->profile_id, strerror(-stage_rc));
            return -1;
        }
    }

    pthread_mutex_lock(&g_key_mutex);
    cached_slot = b->hs_cache_next;
    b->hs_cache_next = (b->hs_cache_next + 1) % PQC_HS_CACHE_SLOTS;
    free(b->hs_cache[cached_slot].response);
    memset(&b->hs_cache[cached_slot], 0, sizeof(b->hs_cache[cached_slot]));
    b->hs_cache[cached_slot].response = response_copy;
    b->hs_cache[cached_slot].response_len = response_len;
    b->hs_cache[cached_slot].session_id = msg->session_id;
    memcpy(b->hs_cache[cached_slot].hello_hash, hello_hash, sizeof(hello_hash));
    if (!is_rekey)
        memcpy(b->hs_cache[cached_slot].master_key, derived_master,
               sizeof(derived_master));
    b->hs_cache[cached_slot].agreed_key_id = init_agreed_key_id;
    b->hs_cache[cached_slot].valid = true;
    b->hs_cache[cached_slot].is_rekey = is_rekey;
    pthread_mutex_unlock(&g_key_mutex);

    return pqc_hs_send_cached_response(b, cached_slot, msg->session_id,
                                       hello_hash, sockfd, peeraddr, false);
}

static int pqc_hs_send_rekey_control(policy_key_binding_t *b, int sockfd,
                                     const struct sockaddr_in *peeraddr,
                                     const char *my_priv, uint8_t msg_type,
                                     uint64_t epoch, uint8_t key_id,
                                     const uint8_t fingerprint[32])
{
    uint8_t buffer[PQC_HS_MSG_MAX_SZ] = {0};
    uint8_t raw_priv[8192];
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
    pqc_rekey_wire_t *wire = (pqc_rekey_wire_t *)msg->payload;
    uint64_t epoch_be;
    size_t raw_priv_sz = 0;
    size_t msg_len;
    int sig_sz = 0;
    ssize_t sent;

    if (!b || sockfd < 0 || !peeraddr || !my_priv || !epoch || !key_id ||
        !fingerprint ||
        (msg_type != PQC_HS_MSG_REKEY_READY &&
         msg_type != PQC_HS_MSG_REKEY_COMMIT &&
         msg_type != PQC_HS_MSG_REKEY_COMMIT_ACK &&
         msg_type != PQC_HS_MSG_REKEY_ABORT))
        return -EINVAL;
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = msg_type;
    msg->session_id = (uint32_t)epoch;
    msg->profile_id = (uint32_t)b->profile_id;
    msg->data_len = PQC_REKEY_WIRE_SIZE;
    epoch_be = htobe64(epoch);
    memcpy(wire->epoch_be, &epoch_be, sizeof(epoch_be));
    wire->key_id = key_id;
    memcpy(wire->key_fingerprint, fingerprint,
           sizeof(wire->key_fingerprint));
    trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
    if (!raw_priv_sz ||
        pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                            msg->payload + msg->data_len,
                            &sig_sz) != TRF_PQC_OK ||
        sig_sz <= 0 || (size_t)sig_sz > UINT16_MAX)
        return -EKEYREJECTED;
    msg->sig_len = (uint16_t)sig_sz;
    msg_len = sizeof(*msg) + msg->data_len + (size_t)sig_sz;
    sent = sendto(sockfd, msg, msg_len, 0,
                  (const struct sockaddr *)peeraddr, sizeof(*peeraddr));
    if (sent != (ssize_t)msg_len)
        return sent < 0 ? -errno : -EIO;
    return 0;
}

static int pqc_hs_verify_rekey_control(policy_key_binding_t *b,
                                       const struct pqc_hs_msg *msg,
                                       const char *peer_pub,
                                       uint64_t *epoch, uint8_t *key_id,
                                       uint8_t fingerprint[32])
{
    const pqc_rekey_wire_t *wire;
    uint8_t raw_pub[8192];
    uint64_t epoch_be;
    size_t raw_pub_sz = 0;

    if (!b || !msg || !peer_pub || !epoch || !key_id || !fingerprint ||
        msg->magic != PQC_HS_MAGIC || msg->session_id == 0 ||
        !pqc_hs_profile_matches(msg->profile_id, b->profile_id) ||
        msg->data_len != PQC_REKEY_WIRE_SIZE || !msg->sig_len)
        return -EINVAL;
    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
    if (!raw_pub_sz ||
        pqc_hs_verify_message(raw_pub, raw_pub_sz, msg) != TRF_PQC_OK)
        return -EKEYREJECTED;
    wire = (const pqc_rekey_wire_t *)msg->payload;
    memcpy(&epoch_be, wire->epoch_be, sizeof(epoch_be));
    *epoch = be64toh(epoch_be);
    *key_id = wire->key_id;
    memcpy(fingerprint, wire->key_fingerprint, 32);
    if (!*epoch || !*key_id || msg->session_id != (uint32_t)*epoch)
        return -EPROTO;
    return 0;
}

static int pqc_hs_handle_rekey_control(policy_key_binding_t *b, int sockfd,
                                       const struct sockaddr_in *peeraddr,
                                       const char *my_priv,
                                       const char *peer_pub,
                                       const struct pqc_hs_msg *msg)
{
    uint8_t fingerprint[32];
    uint8_t key_id;
    uint8_t current_key[32];
    uint64_t epoch;
    uint64_t callback_generation = 0;
    bool activated = false;
    int ret;

    ret = pqc_hs_verify_rekey_control(b, msg, peer_pub, &epoch, &key_id,
                                      fingerprint);
    if (ret)
        return ret;

    pthread_mutex_lock(&g_key_mutex);
    if (b->rotation.epoch != epoch || b->rotation.next_id != key_id ||
        memcmp(b->rotation.fingerprint, fingerprint, 32) != 0) {
        pthread_mutex_unlock(&g_key_mutex);
        /* The responder explicitly confirms that this epoch is no longer
         * staged.  Only this authenticated answer makes it safe for the
         * initiator to discard its local NEXT after a long interruption. */
        if (msg->msg_type == PQC_HS_MSG_REKEY_READY &&
            !b->is_initiator)
            return pqc_hs_send_rekey_control(
                b, sockfd, peeraddr, my_priv, PQC_HS_MSG_REKEY_ABORT,
                epoch, key_id, fingerprint);
        return -ESTALE;
    }

    if (msg->msg_type == PQC_HS_MSG_REKEY_READY && !b->is_initiator) {
        ret = pqc_key_rotation_activate(
            &b->rotation, b->profile_id, b->keys, b->key_ids,
            b->key_slots_valid, b->encrypt_key, b->decrypt_key,
            get_time_ms_hs());
        if (!ret) {
            memcpy(current_key, b->encrypt_key, sizeof(current_key));
            callback_generation = b->config_generation;
            b->last_rotation_time = get_time_ms_hs();
            activated = true;
        }
    } else if (msg->msg_type == PQC_HS_MSG_REKEY_COMMIT &&
               b->is_initiator) {
        ret = pqc_key_rotation_activate(
            &b->rotation, b->profile_id, b->keys, b->key_ids,
            b->key_slots_valid, b->encrypt_key, b->decrypt_key,
            get_time_ms_hs());
        if (!ret) {
            pqc_key_rotation_mark_peer_committed(&b->rotation, epoch,
                                                  key_id, fingerprint);
            memcpy(current_key, b->encrypt_key, sizeof(current_key));
            callback_generation = b->config_generation;
            b->last_rotation_time = get_time_ms_hs();
            activated = true;
        }
    } else if (msg->msg_type == PQC_HS_MSG_REKEY_COMMIT_ACK &&
               !b->is_initiator) {
        pqc_key_rotation_mark_peer_committed(&b->rotation, epoch, key_id,
                                              fingerprint);
        ret = 0;
    } else if (msg->msg_type == PQC_HS_MSG_REKEY_ABORT &&
               b->is_initiator &&
               b->rotation.state == PQC_REKEY_NEXT_STAGED) {
        ret = pqc_key_rotation_abort(
            &b->rotation, b->profile_id, b->keys, b->key_ids,
            b->key_slots_valid);
    } else {
        ret = -EPROTO;
    }
    pthread_mutex_unlock(&g_key_mutex);
    if (ret)
        return ret;

    if (activated) {
        sig_pqc_on_key_activated(b->profile_id, current_key,
                                 callback_generation);
        forwarder_pre_diversify_pqc_keys(b->profile_id);
    }
    if (msg->msg_type == PQC_HS_MSG_REKEY_READY)
        return pqc_hs_send_rekey_control(
            b, sockfd, peeraddr, my_priv, PQC_HS_MSG_REKEY_COMMIT,
            epoch, key_id, fingerprint);
    if (msg->msg_type == PQC_HS_MSG_REKEY_COMMIT)
        return pqc_hs_send_rekey_control(
            b, sockfd, peeraddr, my_priv,
            PQC_HS_MSG_REKEY_COMMIT_ACK, epoch, key_id, fingerprint);
    return 0;
}

static int initiate_key_rotation(policy_key_binding_t *b, int sockfd,
                                 struct sockaddr_in *peeraddr,
                                 char *my_priv, char *peer_pub,
                                 int profile_id)
{
    uint8_t pk[2048], sk[4096], ss[128];
    uint8_t buffer[PQC_HS_MSG_MAX_SZ] = {0};
    uint8_t fingerprint[32] = {0};
    uint8_t next_id = 0;
    uint32_t msg_id;
    int pk_sz = 0, sk_sz = 0;
    int payload_tot_sz = 0;
    int sig_sz = 0;
    bool staged = false;
    uint64_t rotation_started;
    struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;

    /* Resume an already staged transaction before trying to generate a new
     * one.  This is required when READY reached the responder (which may
     * already have activated NEXT) but COMMIT was lost. */
    pthread_mutex_lock(&g_key_mutex);
    if (b->rotation.state == PQC_REKEY_NEXT_STAGED) {
        msg_id = (uint32_t)b->rotation.epoch;
        next_id = b->rotation.next_id;
        memcpy(fingerprint, b->rotation.fingerprint,
               sizeof(fingerprint));
        staged = true;
    } else if (b->rotation.state != PQC_REKEY_STABLE) {
        pthread_mutex_unlock(&g_key_mutex);
        return -EBUSY;
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (staged) {
        rotation_started = get_time_ms_hs();
        goto exchange;
    }

    if (trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz) != TRF_PQC_OK ||
        pqc_generate_session_id(&msg_id) != 0)
        return -EIO;
    msg->magic = PQC_HS_MAGIC;
    msg->msg_type = PQC_HS_MSG_REKEY_HELLO;
    msg->session_id = msg_id;
    msg->profile_id = (uint32_t)profile_id;
    msg->data_len = (uint16_t)pk_sz;
    memcpy(msg->payload, pk, (size_t)pk_sz);
    {
        size_t raw_priv_sz = 0;
        uint8_t raw_priv[8192];

        trf_base64_decode(my_priv, raw_priv, &raw_priv_sz);
        if (!raw_priv_sz ||
            pqc_hs_sign_message(raw_priv, raw_priv_sz, msg,
                                msg->payload + pk_sz,
                                &sig_sz) != TRF_PQC_OK)
            return -EKEYREJECTED;
    }
    msg->sig_len = (uint16_t)sig_sz;
    payload_tot_sz = (int)sizeof(*msg) + pk_sz + sig_sz;
    rotation_started = get_time_ms_hs();
    fprintf(stderr,
            "[PQC-REKEY] Profile %d START epoch=%u; CURRENT remains active.\n",
            profile_id, msg_id);

exchange:
    while (pqc_dispatcher_is_running() && !b->thread_exit_sig &&
           get_time_ms_hs() - rotation_started < PQC_HS_GIVEUP_TIMEOUT_MS) {
        int send_rc;

        if (!staged) {
            ssize_t sent = sendto(sockfd, buffer, (size_t)payload_tot_sz, 0,
                                  (const struct sockaddr *)peeraddr,
                                  sizeof(*peeraddr));
            send_rc = sent == payload_tot_sz ? 0 :
                (sent < 0 ? -errno : -EIO);
        } else {
            send_rc = pqc_hs_send_rekey_control(
                b, sockfd, peeraddr, my_priv, PQC_HS_MSG_REKEY_READY,
                (uint64_t)msg_id, next_id, fingerprint);
        }
        if (send_rc != 0) {
            usleep(200000);
            continue;
        }

        {
            uint64_t start_rx = get_time_ms_hs();

            while (pqc_dispatcher_is_running() && !b->thread_exit_sig &&
                   get_time_ms_hs() - start_rx < 1000) {
                uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                pqc_rx_pkt_info_t info;
                const struct pqc_hs_msg *resp = NULL;
                int rx_len = pqc_policy_rx_recv(b, rx_buf,
                                                sizeof(rx_buf), &info, 200);

                if (rx_len <= 0 ||
                    pqc_hs_validate_message(rx_buf, rx_len, &resp) != 0 ||
                    resp->magic != PQC_HS_MAGIC ||
                    !pqc_hs_profile_matches(resp->profile_id, profile_id) ||
                    resp->session_id != msg_id)
                    continue;

                if (!staged && resp->msg_type == PQC_HS_MSG_REKEY_RESP &&
                    resp->data_len > PQC_REKEY_WIRE_SIZE) {
                    const pqc_rekey_wire_t *wire =
                        (const pqc_rekey_wire_t *)resp->payload;
                    uint64_t epoch_be;
                    uint64_t epoch;
                    uint8_t derived_master[32];
                    uint8_t calculated_fp[32];
                    uint8_t raw_pub[8192];
                    size_t raw_pub_sz = 0;
                    int stage_rc;

                    trf_base64_decode(peer_pub, raw_pub, &raw_pub_sz);
                    memcpy(&epoch_be, wire->epoch_be, sizeof(epoch_be));
                    epoch = be64toh(epoch_be);
                    if (!raw_pub_sz || epoch != (uint64_t)msg_id ||
                        !wire->key_id ||
                        pqc_hs_verify_message(raw_pub, raw_pub_sz, resp) !=
                            TRF_PQC_OK ||
                        trf_kem_decapsulate(
                            sk, sk_sz,
                            resp->payload + PQC_REKEY_WIRE_SIZE,
                            resp->data_len - PQC_REKEY_WIRE_SIZE,
                            ss) != TRF_PQC_OK)
                        continue;
                    derive_traffic_key(ss, 32, derived_master);
                    if (trf_calculate_digest(
                            DIGEST_TYPE_SHA256, derived_master,
                            sizeof(derived_master), calculated_fp) !=
                            TRF_PQC_OK ||
                        memcmp(calculated_fp, wire->key_fingerprint,
                               sizeof(calculated_fp)) != 0)
                        continue;
                    next_id = wire->key_id;
                    memcpy(fingerprint, calculated_fp,
                           sizeof(fingerprint));
                    pthread_mutex_lock(&g_key_mutex);
                    stage_rc = pqc_key_rotation_stage(
                        &b->rotation, profile_id, epoch, next_id,
                        derived_master, fingerprint, b->keys, b->key_ids,
                        b->key_slots_valid, get_time_ms_hs());
                    pthread_mutex_unlock(&g_key_mutex);
                    if (stage_rc != 0)
                        goto failed;
                    staged = true;
                    continue;
                }

                if (staged &&
                    resp->msg_type == PQC_HS_MSG_REKEY_COMMIT) {
                    int control_rc = pqc_hs_handle_rekey_control(
                        b, sockfd, peeraddr, my_priv, peer_pub, resp);

                    if (control_rc == 0)
                        return 0;
                } else if (staged &&
                           resp->msg_type == PQC_HS_MSG_REKEY_ABORT) {
                    int control_rc = pqc_hs_handle_rekey_control(
                        b, sockfd, peeraddr, my_priv, peer_pub, resp);

                    if (control_rc == 0)
                        return -ECANCELED;
                }
            }
        }
    }

failed:
    /* Once READY may have reached the peer, aborting NEXT locally is unsafe:
     * the responder may already be transmitting with that key.  Preserve
     * CURRENT+NEXT and resume this same epoch on the next worker iteration. */
    if (staged)
        return -EAGAIN;
    fprintf(stderr,
            "[PQC-REKEY] Profile %d FAILED; CURRENT retained.\n",
            profile_id);
    return -ETIMEDOUT;
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
    const struct pqc_hs_msg *validated_msg = NULL;

    (void)src_mac;
    if (pqc_hs_validate_message(payload, len, &validated_msg) != 0)
        return;
    const struct pqc_hs_msg *msg = validated_msg;
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
        if (msg->msg_type == PQC_HS_MSG_KEEPALIVE && b->is_tunnel) {
            pqc_hs_keepalive_status_t peer_status;
            uint8_t local_state;
            uint8_t local_fingerprint[PQC_HS_KEY_FINGERPRINT_SZ];
            const char *recovery_reason = NULL;
            bool peer_was_unreachable;
            int verify_rc;

            memset(&peer_status, 0, sizeof(peer_status));
            verify_rc = pqc_hs_verify_l3_keepalive_locked(
                b, msg, &peer_status);
            if (verify_rc != 0) {
                if (pqc_hs_diag_changed(&b->keepalive_rx_last_error,
                                        verify_rc)) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Rejected unauthenticated/invalid KEM key keepalive for Profile %d: %s.\n",
                            b->profile_id, strerror(-verify_rc));
                }
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }
            if (b->keepalive_rx_last_error != 0) {
                fprintf(stderr,
                        "[PQC-HS-L3] Valid signed keepalive reception restored for Profile %d.\n",
                        b->profile_id);
                b->keepalive_rx_last_error = 0;
            }

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
            b->next_auto_retry_time = 0;
            peer_was_unreachable = b->keepalive_peer_unreachable;
            b->keepalive_peer_unreachable = false;

            if (peer_was_unreachable) {
                fprintf(stderr,
                        "[PQC-HS-L3] Signed keepalive reception restored for Profile %d; evaluating peer key state.\n",
                        b->profile_id);
            }

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
                    peer_status.key_id ==
                        b->key_ids[KEY_SLOT_CURRENT] &&
                    memcmp(local_fingerprint,
                           peer_status.key_fingerprint,
                           sizeof(local_fingerprint)) == 0) {
                    if (b->rotation.state ==
                            PQC_REKEY_ACTIVE_WITH_PREV &&
                        peer_status.key_id ==
                            b->key_ids[KEY_SLOT_CURRENT]) {
                        pqc_key_rotation_mark_peer_committed(
                            &b->rotation, b->rotation.epoch,
                            b->rotation.next_id,
                            b->rotation.fingerprint);
                    }
                    pthread_mutex_unlock(&g_key_mutex);
                    return;
                }
                recovery_reason = "peer key ID/fingerprint mismatch";
            } else if (local_state == PQC_HS_STATE_FAILED) {
                recovery_reason = "local profile has no usable key";
            } else if (peer_status.state == PQC_HS_STATE_FAILED) {
                recovery_reason = "peer reported failed key state";
            }

            if (!recovery_reason) {
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }

            pqc_hs_begin_profile_recovery_locked(
                b, b->last_keepalive_rx_time);
            pqc_flush_rx_queue(b);
            fprintf(stderr,
                    "[PQC-HS-L3] KEM key keepalive triggered automatic recovery for Profile %d (%s). Role=%s.\n",
                    b->profile_id, recovery_reason,
                    b->is_initiator ? "Initiator" : "Responder");
            pthread_mutex_unlock(&g_key_mutex);
            return;
        } else if (msg->msg_type == PQC_HS_MSG_POKE) {
            uint64_t request_id = 0;
            int verify_rc = pqc_hs_verify_request_locked(b, msg,
                                                         &request_id);

            if (verify_rc != 0) {
                if (pqc_hs_diag_changed(&b->request_rx_last_error,
                                        verify_rc)) {
                    fprintf(stderr,
                            "[PQC-HS] Rejected unauthenticated/invalid handshake request for Profile %d: %s.\n",
                            b->profile_id, strerror(-verify_rc));
                }
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }
            b->request_rx_last_error = 0;
            if (request_id == b->peer_request_id) {
                /* The responder retries the same authenticated request until
                 * the state changes.  Duplicates are expected and must not
                 * flood the service journal. */
                pthread_mutex_unlock(&g_key_mutex);
                return;
            }

            b->peer_request_id = request_id;
            pqc_hs_begin_profile_recovery_locked(b, get_time_ms_hs());
            pqc_flush_rx_queue(b);
            fprintf(stderr,
                    "[PQC-HS] Accepted authenticated responder request %016llx. Restarting initiator handshake for Profile %d.\n",
                    (unsigned long long)request_id, b->profile_id);
            pthread_mutex_unlock(&g_key_mutex);
            return;
        } else if (msg->msg_type == PQC_HS_MSG_HELLO) {
            if (b->handshake_give_up) {
                pqc_hs_begin_profile_recovery_locked(
                    b, get_time_ms_hs());
                pqc_flush_rx_queue(b);
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

static void pqc_dispatcher_publish_failure(int error_code) {
    pthread_mutex_lock(&g_key_mutex);
    atomic_store_explicit(&g_dispatcher_running, false,
                          memory_order_release);
    g_dispatcher_state = PQC_RUNTIME_FAILED;
    g_dispatcher_last_error = error_code ? error_code : EIO;
    pthread_cond_broadcast(&g_dispatcher_cond);
    pthread_mutex_unlock(&g_key_mutex);
}

static int pqc_dispatcher_ensure_running(void) {
    struct timespec deadline;
    pthread_t udp_tid;
    int rc;

    pthread_mutex_lock(&g_key_mutex);
    if (g_dispatcher_state == PQC_RUNTIME_RUNNING &&
        pqc_dispatcher_is_running()) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }

    if (g_dispatcher_state != PQC_RUNTIME_STARTING) {
        g_dispatcher_state = PQC_RUNTIME_STARTING;
        g_dispatcher_last_error = 0;
        atomic_store_explicit(&g_dispatcher_running, false,
                              memory_order_release);
        rc = pthread_create(&udp_tid, NULL, pqc_udp_dispatcher_thread, NULL);
        if (rc != 0) {
            g_dispatcher_state = PQC_RUNTIME_FAILED;
            g_dispatcher_last_error = rc;
            pthread_cond_broadcast(&g_dispatcher_cond);
            pthread_mutex_unlock(&g_key_mutex);
            fprintf(stderr,
                    "[PQC-HS] ERROR starting UDP dispatcher thread: %s\n",
                    strerror(rc));
            return -rc;
        }
        pthread_detach(udp_tid);
    }

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    while (g_dispatcher_state == PQC_RUNTIME_STARTING) {
        rc = pthread_cond_timedwait(&g_dispatcher_cond, &g_key_mutex,
                                    &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g_key_mutex);
            fprintf(stderr,
                    "[PQC-HS] UDP dispatcher did not become ready within 2 seconds.\n");
            return -ETIMEDOUT;
        }
    }

    if (g_dispatcher_state != PQC_RUNTIME_RUNNING ||
        !pqc_dispatcher_is_running()) {
        rc = g_dispatcher_last_error ? g_dispatcher_last_error : EIO;
        pthread_mutex_unlock(&g_key_mutex);
        return -rc;
    }
    pthread_mutex_unlock(&g_key_mutex);
    return 0;
}

static int pqc_interface_ipv4_ready(const char *ifname,
                                    const char *local_ip) {
    struct ifreq ifr;
    struct sockaddr_in *addr;
    struct in_addr expected;
    int sockfd;
    int saved_errno;

    if (!ifname || !ifname[0] || strlen(ifname) >= IFNAMSIZ ||
        !local_ip || inet_pton(AF_INET, local_ip, &expected) != 1)
        return -EINVAL;
    if (if_nametoindex(ifname) == 0)
        return -ENODEV;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        saved_errno = errno;
        close(sockfd);
        return -saved_errno;
    }
    if (!(ifr.ifr_flags & IFF_UP)) {
        close(sockfd);
        return -ENETDOWN;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        saved_errno = errno;
        close(sockfd);
        return saved_errno == EADDRNOTAVAIL ? -EADDRNOTAVAIL :
                                              -saved_errno;
    }
    close(sockfd);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    if (addr->sin_family != AF_INET ||
        addr->sin_addr.s_addr != expected.s_addr)
        return -EADDRNOTAVAIL;
    return 0;
}

static void* pqc_udp_dispatcher_thread(void* arg) {
    (void)arg;
    int runtime_error = 0;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        int saved_errno = errno;
        perror("[PQC-DISPATCHER] Socket creation failed");
        pqc_dispatcher_publish_failure(saved_errno);
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
        int saved_errno = errno;
        perror("[PQC-DISPATCHER] Bind failed (Port 7090)");
        close(sockfd);
        pqc_dispatcher_publish_failure(saved_errno);
        return NULL;
    }

    pthread_mutex_lock(&g_key_mutex);
    atomic_store_explicit(&g_dispatcher_running, true,
                          memory_order_release);
    g_dispatcher_state = PQC_RUNTIME_RUNNING;
    g_dispatcher_last_error = 0;
    pthread_cond_broadcast(&g_dispatcher_cond);
    pthread_mutex_unlock(&g_key_mutex);

    uint8_t buffer[PQC_HS_MSG_MAX_SZ];
    struct sockaddr_in clientaddr;
    socklen_t addr_len = sizeof(clientaddr);

    fprintf(stderr, "[PQC-DISPATCHER] UDP Listener running on port %d\n", PQC_HS_PORT);

    while (pqc_dispatcher_is_running()) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addr_len);
        if (n > 0) {
            sig_pqc_feed_rx_packet(buffer, n, NULL);
            continue;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR) {
            runtime_error = errno;
            fprintf(stderr, "[PQC-DISPATCHER] recvfrom failed: %s\n",
                    strerror(runtime_error));
            break;
        }
        usleep(10000);
    }

    close(sockfd);
    pthread_mutex_lock(&g_key_mutex);
    atomic_store_explicit(&g_dispatcher_running, false,
                          memory_order_release);
    if (g_dispatcher_state == PQC_RUNTIME_RUNNING) {
        g_dispatcher_state = PQC_RUNTIME_FAILED;
        g_dispatcher_last_error = runtime_error ? runtime_error : ECONNRESET;
    }
    pthread_cond_broadcast(&g_dispatcher_cond);
    pthread_mutex_unlock(&g_key_mutex);
    return NULL;
}

static void pqc_worker_publish_state(policy_key_binding_t *b,
                                     pqc_runtime_state_t state,
                                     int error_code,
                                     bool started) {
    pthread_mutex_lock(&g_key_mutex);
    b->worker_state = state;
    b->worker_last_error = error_code;
    b->thread_started = started;
    pthread_cond_broadcast(&g_worker_state_cond);
    pthread_mutex_unlock(&g_key_mutex);
}

/* g_key_mutex must be held. */
static int pqc_stop_worker_locked(policy_key_binding_t *b, int timeout_ms) {
    struct timespec deadline;

    if (!b->thread_started) {
        b->thread_exit_sig = false;
        return 0;
    }

    b->thread_exit_sig = true;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    while (b->thread_started) {
        int rc = pthread_cond_timedwait(&g_worker_state_cond, &g_key_mutex,
                                        &deadline);
        if (rc == ETIMEDOUT && b->thread_started)
            return -ETIMEDOUT;
        if (rc != 0 && rc != EINTR)
            return -rc;
    }

    b->thread_exit_sig = false;
    return 0;
}

static void* pqc_policy_handshake_worker_run(void *arg) {
    policy_key_binding_t *b = (policy_key_binding_t *)arg;
    int profile_id = b->profile_id;
    uint64_t next_request_time = 0;
    uint64_t next_keepalive_time = 0;
    uint8_t last_keepalive_state = 0;
    int last_resolved_role = -1;
    int last_keepalive_send_status = 0;
    int last_hello_send_status = INT_MIN;
    int last_request_send_status = INT_MIN;
    int last_prepare_error = 0;

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
        pqc_worker_publish_state(b, PQC_RUNTIME_FAILED, EINVAL, false);
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
        int saved_errno = errno;
        perror("[PQC-WORKER] UDP Socket creation failed");
        free(my_priv); free(my_pub); free(peer_pub);
        pqc_worker_publish_state(b, PQC_RUNTIME_FAILED, saved_errno, false);
        return NULL;
    }

    if (wan_ifname[0] == '\0' ||
        setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, wan_ifname,
                   strlen(wan_ifname) + 1) < 0) {
        int saved_errno = errno ? errno : EINVAL;
        fprintf(stderr, "[PQC-WORKER] Cannot bind socket to tunnel %s: %s\n",
                wan_ifname[0] ? wan_ifname : "<empty>",
                strerror(saved_errno));
        close(sockfd);
        free(my_priv); free(my_pub); free(peer_pub);
        pqc_worker_publish_state(b, PQC_RUNTIME_FAILED, saved_errno, false);
        return NULL;
    }

    {
        struct sockaddr_in localaddr;

        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = 0;
        int bind_error = 0;
        if (inet_pton(AF_INET, local_ip, &localaddr.sin_addr) != 1)
            bind_error = EINVAL;
        else if (bind(sockfd, (const struct sockaddr *)&localaddr,
                      sizeof(localaddr)) < 0)
            bind_error = errno;
        if (bind_error != 0) {
            fprintf(stderr, "[PQC-WORKER] Cannot bind %s on %s: %s\n",
                    local_ip, wan_ifname, strerror(bind_error));
            close(sockfd);
            free(my_priv); free(my_pub); free(peer_pub);
            pqc_worker_publish_state(b, PQC_RUNTIME_FAILED, bind_error,
                                     false);
            return NULL;
        }
    }

    struct sockaddr_in peeraddr;
    memset(&peeraddr, 0, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(PQC_HS_PORT);
    if (inet_pton(AF_INET, peer_ip, &peeraddr.sin_addr) != 1) {
        fprintf(stderr, "[PQC-WORKER] Invalid peer IP '%s' for Profile %d.\n",
                peer_ip, profile_id);
        close(sockfd);
        free(my_priv); free(my_pub); free(peer_pub);
        pqc_worker_publish_state(b, PQC_RUNTIME_FAILED, EINVAL, false);
        return NULL;
    }

    pqc_worker_publish_state(b, PQC_RUNTIME_RUNNING, 0, true);

    while (pqc_dispatcher_is_running() && !b->thread_exit_sig) {
        uint64_t loop_now = get_time_ms_hs();
        bool keepalive_enabled;
        bool handshake_give_up;
        bool keepalive_timeout_detected = false;
        bool auto_retry_started = false;
        bool flush_rx_queue = false;
        uint8_t keepalive_state = PQC_HS_STATE_FAILED;

        pthread_mutex_lock(&g_key_mutex);
        if (b->keepalive_enabled && b->key_ready) {
            uint64_t monitor_from = b->last_keepalive_rx_time != 0
                ? b->last_keepalive_rx_time
                : b->keepalive_monitor_start_time;

            if (monitor_from != 0 && loop_now >= monitor_from &&
                loop_now - monitor_from >=
                    PQC_HS_KEEPALIVE_TIMEOUT_MS &&
                !b->keepalive_peer_unreachable) {
                /* A liveness timeout does not prove that either traffic key
                 * is invalid.  Retain CURRENT and continue only the cheap
                 * signed keepalive probe.  A valid peer status can later
                 * decide whether a standard handshake is actually needed. */
                b->keepalive_peer_unreachable = true;
                keepalive_timeout_detected = true;
            }
        }

        if (b->handshake_give_up) {
            if (b->next_auto_retry_time == 0) {
                b->next_auto_retry_time =
                    loop_now + PQC_HS_AUTO_RETRY_INTERVAL_MS;
            } else if (loop_now >= b->next_auto_retry_time) {
                pqc_hs_begin_profile_recovery_locked(b, loop_now);
                auto_retry_started = true;
                flush_rx_queue = true;
            }
        }

        keepalive_enabled = b->keepalive_enabled;
        if (keepalive_enabled)
            keepalive_state = pqc_hs_l3_state_locked(b);
        handshake_give_up = b->handshake_give_up;
        pthread_mutex_unlock(&g_key_mutex);

        if (flush_rx_queue)
            pqc_flush_rx_queue(b);
        if (keepalive_timeout_detected) {
            fprintf(stderr,
                    "[PQC-HS-L3] Profile %d missed %d keepalive intervals; peer marked unreachable and CURRENT retained.\n",
                    profile_id, PQC_HS_KEEPALIVE_MISSED_LIMIT);
        } else if (auto_retry_started) {
            fprintf(stderr,
                    "[PQC-HS-L3] Profile %d automatically retrying after handshake give-up as %s.\n",
                    profile_id,
                    is_initiator ? "Initiator" : "Responder");
        }

        if (keepalive_enabled && next_keepalive_time == 0) {
            next_keepalive_time =
                loop_now + PQC_HS_KEEPALIVE_INTERVAL_MS;
            last_keepalive_state = keepalive_state;
        } else if (keepalive_enabled &&
                   (keepalive_state != last_keepalive_state ||
                    loop_now >= next_keepalive_time)) {
            int keepalive_rc = pqc_hs_send_l3_keepalive(
                b, sockfd, &peeraddr, my_priv);

            last_keepalive_state = keepalive_state;
            next_keepalive_time =
                loop_now + PQC_HS_KEEPALIVE_INTERVAL_MS;
            if (keepalive_rc != -EAGAIN &&
                keepalive_rc != last_keepalive_send_status) {
                if (keepalive_rc == 0) {
                    fprintf(stderr,
                            "[PQC-HS-L3] Signed keepalive transmission recovered for Profile %d.\n",
                            profile_id);
                } else {
                    fprintf(stderr,
                            "[PQC-HS-L3] Failed to send signed KEM key keepalive for Profile %d: %s.\n",
                            profile_id, strerror(-keepalive_rc));
                }
                last_keepalive_send_status = keepalive_rc;
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

                    if (wan_ifname[0] != '\0') {
                        struct ifreq ifr;
                        size_t ifname_len = strnlen(wan_ifname,
                                                   IFNAMSIZ - 1);
                        memset(&ifr, 0, sizeof(ifr));
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
                        if (last_resolved_role != (int)is_initiator) {
                            fprintf(stderr, "[PQC-WORKER-L3] Profile %d: Dynamic role resolved. Local IP: %s (%u), Peer IP: %s (%u). Resolved Role: %s\n",
                                    profile_id, local_ip_str, local_ip_num, peer_ip, peer_ip_num,
                                    is_initiator ? "INITIATOR" : "RESPONDER");
                            last_resolved_role = (int)is_initiator;
                        }
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
                    if (last_prepare_error != 1) {
                        fprintf(stderr,
                                "[PQC-HS-L3] Failed to create KEM/session material for Profile %d.\n",
                                profile_id);
                        last_prepare_error = 1;
                    }
                    usleep(500000);
                    continue;
                }
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                pqc_hs_init_hello_wire_t *init_wire =
                    (pqc_hs_init_hello_wire_t *)msg->payload;
                msg->magic = PQC_HS_MAGIC;
                msg->msg_type = PQC_HS_MSG_HELLO;
                msg->session_id = session_id;
                msg->profile_id = profile_id;
                msg->data_len = (uint16_t)(sizeof(*init_wire) +
                                            (size_t)pk_sz);
                memset(init_wire, 0, sizeof(*init_wire));
                init_wire->version = PQC_HS_INIT_WIRE_VERSION;
                memcpy(msg->payload + sizeof(*init_wire), pk,
                       (size_t)pk_sz);

                pthread_mutex_lock(&g_key_mutex);
                if (b->key_slots_valid[KEY_SLOT_CURRENT]) {
                    init_wire->flags |= PQC_HS_INIT_HAS_CURRENT;
                    init_wire->current_key_id =
                        b->key_ids[KEY_SLOT_CURRENT];
                }
                if (b->key_slots_valid[KEY_SLOT_PREV]) {
                    init_wire->flags |= PQC_HS_INIT_HAS_PREVIOUS;
                    init_wire->previous_key_id =
                        b->key_ids[KEY_SLOT_PREV];
                }
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
                                        msg->payload + msg->data_len,
                                        &sig_sz) != TRF_PQC_OK) {
                    pthread_mutex_unlock(&g_key_mutex);
                    if (last_prepare_error != 2) {
                        fprintf(stderr, "[PQC-HS-L3] Failed to sign HELLO for Profile %d.\n",
                                profile_id);
                        last_prepare_error = 2;
                    }
                    usleep(500000);
                    continue;
                }
                msg->sig_len = (uint16_t)sig_sz;
                pthread_mutex_unlock(&g_key_mutex);
                last_prepare_error = 0;

                while (pqc_dispatcher_is_running() && !b->key_ready && !b->thread_exit_sig) {
                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = get_time_ms_hs();
                    }
                    if (get_time_ms_hs() - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                        fprintf(stderr, "[PQC-HS-L3] Handshake timed out after %d seconds. Giving up on Profile %d.\n",
                                PQC_HS_GIVEUP_TIMEOUT_MS / 1000, profile_id);
                        sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Peer connection timeout.");
                        b->handshake_give_up = true;
                        break;
                    }
                    size_t hello_len = sizeof(struct pqc_hs_msg) +
                                       (size_t)msg->data_len +
                                       (size_t)sig_sz;
                    ssize_t sent = sendto(
                        sockfd, buffer, hello_len, 0,
                        (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
                    int send_status = sent == (ssize_t)hello_len
                        ? 0 : -(sent < 0 ? errno : EMSGSIZE);

                    if (send_status != last_hello_send_status) {
                        if (send_status == 0) {
                            fprintf(stderr,
                                    "[PQC-WORKER-L3] Initiator Profile %d started sending HELLO session %u.\n",
                                    profile_id, session_id);
                        } else {
                            fprintf(stderr,
                                    "[PQC-HS-L3] Failed to send HELLO for Profile %d, session %u: %s (len=%zu).\n",
                                    profile_id, session_id,
                                    strerror(-send_status), hello_len);
                        }
                        last_hello_send_status = send_status;
                    }
                    if (sent != (ssize_t)hello_len) {
                        int send_error = sent < 0 ? errno : EMSGSIZE;
                        if (send_error == EMSGSIZE) {
                            sig_pqc_write_log(
                                profile_id, b->key_id, PQC_LOG_LEVEL_ERROR,
                                PQC_LOG_STATUS_FAILED,
                                "Handshake HELLO exceeds path/socket MTU.");
                            b->handshake_give_up = true;
                            break;
                        }
                        usleep(200000);
                        continue;
                    }

                    uint64_t start_rx = get_time_ms_hs();
                    while (pqc_dispatcher_is_running() && get_time_ms_hs() - start_rx < 3000 && !b->key_ready && !b->thread_exit_sig) {
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

                                if (pqc_hs_verify_message(raw_pub, raw_pub_sz,
                                                          resp) ==
                                        TRF_PQC_OK &&
                                    resp->data_len >
                                        sizeof(pqc_hs_init_resp_wire_t)) {
                                    const pqc_hs_init_resp_wire_t *resp_wire =
                                        (const pqc_hs_init_resp_wire_t *)
                                            resp->payload;

                                    if (resp_wire->version !=
                                            PQC_HS_INIT_WIRE_VERSION ||
                                        resp_wire->agreed_key_id == 0)
                                        continue;
                                    if (trf_kem_decapsulate(
                                            sk, sk_sz,
                                            resp->payload +
                                                sizeof(*resp_wire),
                                            resp->data_len -
                                                sizeof(*resp_wire),
                                            ss) == TRF_PQC_OK) {
                                        uint8_t derived_master[PQC_TRAFFIC_KEY_SZ];
                                        uint8_t calculated_fingerprint[
                                            PQC_HS_KEY_FINGERPRINT_SZ];
                                        derive_traffic_key(ss, 32, derived_master);

                                        if (trf_calculate_digest(
                                                DIGEST_TYPE_SHA256,
                                                derived_master,
                                                sizeof(derived_master),
                                                calculated_fingerprint) !=
                                                TRF_PQC_OK ||
                                            memcmp(calculated_fingerprint,
                                                   resp_wire->key_fingerprint,
                                                   sizeof(calculated_fingerprint)) !=
                                                0)
                                            continue;

                                        uint64_t callback_generation;

                                        pthread_mutex_lock(&g_key_mutex);
                                        handle_handshake_success(
                                            b, derived_master,
                                            resp_wire->agreed_key_id,
                                            "Initiator");
                                        callback_generation = b->config_generation;
                                        pthread_mutex_unlock(&g_key_mutex);

                                        sig_pqc_on_key_ready(profile_id,
                                                             derived_master,
                                                             callback_generation);
                                        forwarder_pre_diversify_pqc_keys(profile_id);
                                        break;
                                    }
                                }
                            }
                        }
                        usleep(10000);
                    }
                }
            } else {
                if (b->handshake_start_time == 0) {
                    b->handshake_start_time = get_time_ms_hs();
                }
                fprintf(stderr, "[PQC-WORKER-L3] Responder (Profile %d) listening for HELLO...\n", profile_id);
                while (pqc_dispatcher_is_running() && !b->key_ready && !b->thread_exit_sig) {
                    uint64_t now = get_time_ms_hs();
                    bool request_now;

                    if (b->handshake_start_time == 0) {
                        b->handshake_start_time = now;
                    }
                    if (now - b->handshake_start_time > PQC_HS_GIVEUP_TIMEOUT_MS) {
                        fprintf(stderr, "[PQC-HS-L3] Responder timed out waiting for HELLO on Profile %d.\n", profile_id);
                        sig_pqc_write_log(profile_id, b->key_id, PQC_LOG_LEVEL_ERROR, PQC_LOG_STATUS_FAILED, "Handshake timeout. No HELLO received from Peer.");
                        b->handshake_give_up = true;
                        break;
                    }

                    request_now = atomic_exchange_explicit(
                                      &b->send_poke, false,
                                      memory_order_acq_rel) ||
                                  next_request_time == 0 ||
                                  now >= next_request_time;
                    if (request_now) {
                        int request_rc = pqc_hs_send_handshake_request(
                            b, sockfd, &peeraddr, my_priv);

                        next_request_time = now + PQC_HS_REQUEST_RETRY_MS;
                        if (request_rc != last_request_send_status) {
                            if (request_rc == 0) {
                                fprintf(stderr,
                                        "[PQC-HS-L3] Responder Profile %d started sending authenticated handshake requests.\n",
                                        profile_id);
                            } else {
                                fprintf(stderr,
                                        "[PQC-HS-L3] Responder Profile %d failed to send authenticated handshake request: %s.\n",
                                        profile_id, strerror(-request_rc));
                            }
                            last_request_send_status = request_rc;
                        }
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
                bool resume_rekey;

                pthread_mutex_lock(&g_key_mutex);
                resume_rekey = pqc_key_rotation_in_progress(&b->rotation);
                pthread_mutex_unlock(&g_key_mutex);
                if (b->last_sent_time > 0 && (now - b->last_sent_time < 10000) && (now - b->last_recv_time > 15000)) {
                    fprintf(stderr, "[PQC-HS-L3] Self-healing triggered (Initiator): active TX but no RX. Resetting key for Profile %d.\n", profile_id);
                    pthread_mutex_lock(&g_key_mutex);
                    b->key_ready = false;
                    b->last_sent_time = 0;
                    b->last_recv_time = 0;
                    pthread_mutex_unlock(&g_key_mutex);
                } else if (b->l2_rekey_enabled &&
                           (resume_rekey ||
                           now - b->last_rotation_time >
                               KEY_ROTATION_INTERVAL_MS)) {
                    int rotation_rc = initiate_key_rotation(
                        b, sockfd, &peeraddr, my_priv, peer_pub,
                        profile_id);

                    if (rotation_rc != 0 && rotation_rc != -EAGAIN)
                        sig_pqc_write_log(
                            profile_id, b->key_id, PQC_LOG_LEVEL_ERROR,
                            PQC_LOG_STATUS_ROTATION_FAILED,
                            "Session key rotation failed; current key retained.");
                    if (rotation_rc != -EAGAIN) {
                        pthread_mutex_lock(&g_key_mutex);
                        b->last_rotation_time = get_time_ms_hs();
                        pthread_mutex_unlock(&g_key_mutex);
                    }
                }
                usleep(500000);
            } else {
                uint8_t rx_buf[PQC_HS_MSG_MAX_SZ];
                pqc_rx_pkt_info_t info;
                int rx_len = pqc_policy_rx_recv(b, rx_buf, sizeof(rx_buf), &info, 200);
                if (rx_len > 0) {
                    const struct pqc_hs_msg *msg = NULL;
                    if (pqc_hs_validate_message(rx_buf, rx_len, &msg) == 0 &&
                        msg->magic == PQC_HS_MAGIC) {
                        if (msg->msg_type == PQC_HS_MSG_REKEY_HELLO) {
                            pqc_hs_handle_responder_hello(
                                b, sockfd, &peeraddr, rx_buf, rx_len,
                                &my_priv, &peer_pub);
                        } else if (msg->msg_type == PQC_HS_MSG_REKEY_READY ||
                                   msg->msg_type ==
                                       PQC_HS_MSG_REKEY_COMMIT_ACK) {
                            int control_rc = pqc_hs_handle_rekey_control(
                                b, sockfd, &peeraddr, my_priv, peer_pub,
                                msg);

                            if (control_rc != 0 && control_rc != -ESTALE)
                                fprintf(stderr,
                                        "[PQC-REKEY] Profile %d rejected control type=%u: %s.\n",
                                        profile_id, msg->msg_type,
                                        strerror(-control_rc));
                        }
                    }
                }
                usleep(10000);
            }
        }

        pthread_mutex_lock(&g_key_mutex);
        {
            uint64_t now_ms = get_time_ms_hs();

            /* A responder may stage NEXT and then never receive READY (peer
             * reboot, packet loss, or an abandoned negotiation).  Expire
             * only that uncommitted NEXT; CURRENT remains forwarding. */
            if (b->rotation.state == PQC_REKEY_NEXT_STAGED &&
                b->rotation.started_ms &&
                now_ms - b->rotation.started_ms >=
                    PQC_REKEY_NEGOTIATION_TIMEOUT_MS) {
                uint64_t expired_epoch = b->rotation.epoch;
                int abort_rc = pqc_key_rotation_abort(
                    &b->rotation, profile_id, b->keys, b->key_ids,
                    b->key_slots_valid);

                if (abort_rc == 0) {
                    for (int i = 0; i < PQC_HS_CACHE_SLOTS; i++) {
                        if (!b->hs_cache[i].valid ||
                            !b->hs_cache[i].is_rekey ||
                            b->hs_cache[i].session_id !=
                                (uint32_t)expired_epoch)
                            continue;
                        free(b->hs_cache[i].response);
                        memset(&b->hs_cache[i], 0,
                               sizeof(b->hs_cache[i]));
                    }
                }
            }
            int retire_rc = pqc_key_rotation_maybe_retire(
                &b->rotation, profile_id, b->keys, b->key_ids,
                b->key_slots_valid, now_ms);

            if (retire_rc == 0) {
                int idx = b - g_policy_bindings;
                if (idx >= 0 && idx < MAX_POLICY_BINDINGS)
                    g_policy_key_version[idx]++;
            }
        }
        pthread_mutex_unlock(&g_key_mutex);
    }
    close(sockfd);
    free(my_priv);
    free(my_pub);
    free(peer_pub);
    pqc_worker_publish_state(
        b, b->thread_exit_sig ? PQC_RUNTIME_STOPPED : PQC_RUNTIME_FAILED,
        b->thread_exit_sig ? 0 : EPIPE, false);
    return NULL;
}

int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip) {
    char configured_ifname[64] = {0};
    char configured_local_ip[64] = {0};
    policy_key_binding_t *binding = NULL;
    struct timespec worker_deadline;
    int binding_idx = -1;
    int rc;

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings_active[i] &&
            g_policy_bindings[i].profile_id == profile_id) {
            binding = &g_policy_bindings[i];
            binding_idx = i;
            break;
        }
    }
    if (!binding || !binding->local_priv || !binding->local_pub ||
        !binding->peer_pub) {
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] Profile %d has no active, complete PQC binding.\n",
                profile_id);
        return -ENOENT;
    }

    if (wan_ifname && wan_ifname[0] != '\0') {
        snprintf(binding->wan_ifname, sizeof(binding->wan_ifname), "%s",
                 wan_ifname);
    }
    if (peer_ip && peer_ip[0] != '\0') {
        snprintf(binding->peer_ip, sizeof(binding->peer_ip), "%s", peer_ip);
    }
    snprintf(configured_ifname, sizeof(configured_ifname), "%s",
             binding->wan_ifname);
    snprintf(configured_local_ip, sizeof(configured_local_ip), "%s",
             binding->local_ip);
    pthread_mutex_unlock(&g_key_mutex);

    rc = pqc_interface_ipv4_ready(configured_ifname, configured_local_ip);
    if (rc != 0) {
        pthread_mutex_lock(&g_key_mutex);
        if (binding_idx < g_policy_bindings_count &&
            !g_policy_bindings[binding_idx].thread_started) {
            g_policy_bindings[binding_idx].worker_state = PQC_RUNTIME_FAILED;
            g_policy_bindings[binding_idx].worker_last_error = -rc;
        }
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] Profile %d is not ready: interface %s must be UP with local IP %s (%s).\n",
                profile_id, configured_ifname[0] ? configured_ifname : "<empty>",
                configured_local_ip[0] ? configured_local_ip : "<empty>",
                strerror(-rc));
        return rc;
    }

    rc = pqc_dispatcher_ensure_running();
    if (rc != 0) {
        pthread_mutex_lock(&g_key_mutex);
        if (binding_idx < g_policy_bindings_count &&
            !g_policy_bindings[binding_idx].thread_started) {
            g_policy_bindings[binding_idx].worker_state = PQC_RUNTIME_FAILED;
            g_policy_bindings[binding_idx].worker_last_error = -rc;
        }
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] Profile %d cannot start because UDP dispatcher is unavailable: %s\n",
                profile_id, strerror(-rc));
        return rc;
    }

    pthread_mutex_lock(&g_key_mutex);
    if (binding_idx >= g_policy_bindings_count ||
        !g_policy_bindings_active[binding_idx] ||
        g_policy_bindings[binding_idx].profile_id != profile_id) {
        pthread_mutex_unlock(&g_key_mutex);
        return -ENOENT;
    }
    binding = &g_policy_bindings[binding_idx];
    if (binding->thread_started) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }

    binding->thread_exit_sig = false;
    binding->worker_state = PQC_RUNTIME_STARTING;
    binding->worker_last_error = 0;
    binding->thread_started = true;
    rc = pthread_create(&binding->thread_id, NULL,
                        pqc_policy_handshake_worker_run, binding);
    if (rc != 0) {
        binding->thread_started = false;
        binding->worker_state = PQC_RUNTIME_FAILED;
        binding->worker_last_error = rc;
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] ERROR: Failed to spawn Handshake Worker for Profile %d: %s\n",
                profile_id, strerror(rc));
        return -rc;
    }
    pthread_detach(binding->thread_id);

    clock_gettime(CLOCK_REALTIME, &worker_deadline);
    worker_deadline.tv_sec += 1;
    while (binding->worker_state == PQC_RUNTIME_STARTING) {
        int wait_rc = pthread_cond_timedwait(
            &g_worker_state_cond, &g_key_mutex, &worker_deadline);
        if (wait_rc == ETIMEDOUT)
            break;
    }
    if (binding->worker_state == PQC_RUNTIME_FAILED) {
        rc = binding->worker_last_error ? binding->worker_last_error : EIO;
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] Handshake Worker for Profile %d failed during startup: %s\n",
                profile_id, strerror(rc));
        return -rc;
    }
    if (binding->worker_state == PQC_RUNTIME_STOPPED) {
        pthread_mutex_unlock(&g_key_mutex);
        return -ECANCELED;
    }
    if (binding->worker_state == PQC_RUNTIME_STARTING) {
        pthread_mutex_unlock(&g_key_mutex);
        fprintf(stderr,
                "[PQC-HS] Handshake Worker for Profile %d did not report readiness within 1 second.\n",
                profile_id);
        return -ETIMEDOUT;
    }
    pthread_mutex_unlock(&g_key_mutex);

    fprintf(stderr, "[PQC-HS] Spawned Handshake Worker for Profile %d\n",
            profile_id);
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

int sig_pqc_bind_profile(int profile_id, const char *key_id, int role_mode,
                         const char *local_ip, const char *peer_ip,
                         const char *local_fg, const char *peer_fg,
                         const char *wan_ifname,
                         const char *local_priv, const char *local_pub,
                         const char *peer_pub,
                         uint64_t config_generation,
                         bool l2_rekey_enabled) {
    uint64_t new_request_id = 0;
    int request_id_rc;
    char *new_local_priv = local_priv ? strdup(local_priv) : NULL;
    char *new_local_pub = local_pub ? strdup(local_pub) : NULL;
    char *deobf_peer = peer_pub ? strdup(peer_pub) : NULL;

    request_id_rc = pqc_generate_request_id(&new_request_id);
    if (request_id_rc != 0) {
        free(new_local_priv);
        free(new_local_pub);
        free(deobf_peer);
        return request_id_rc;
    }
    if ((local_priv && !new_local_priv) || (local_pub && !new_local_pub) ||
        (peer_pub && !deobf_peer)) {
        free(new_local_priv);
        free(new_local_pub);
        free(deobf_peer);
        return -ENOMEM;
    }

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
        b->worker_state = PQC_RUNTIME_STOPPED;
        b->worker_last_error = 0;
        b->keepalive_rx_last_error = 0;
        b->request_rx_last_error = 0;
        b->hello_rx_last_status = PQC_HS_HELLO_DIAG_OK;
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
        b->send_poke = false;
        b->thread_exit_sig = false;
        b->local_request_id = 0;
        b->peer_request_id = 0;
        b->local_keepalive_seq = 0;
        b->peer_keepalive_epoch = 0;
        b->peer_keepalive_seq = 0;
        b->keepalive_monitor_start_time = 0;
        b->last_keepalive_rx_time = 0;
        b->next_auto_retry_time = 0;
        b->keepalive_enabled = false;
        b->keepalive_peer_unreachable = false;
        for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
            memset(b->keys[slot], 0, PQC_TRAFFIC_KEY_SZ);
            b->key_ids[slot] = 0;
            b->key_slots_valid[slot] = false;
        }
        pqc_key_rotation_init(&b->rotation);
    }
    if (b) {
        if (is_existing) {
            bool changed = false;
            int stop_rc;

            if (b->local_priv && new_local_priv && strcmp(b->local_priv, new_local_priv) != 0) changed = true;
            if (b->local_pub && new_local_pub && strcmp(b->local_pub, new_local_pub) != 0) changed = true;
            if (b->peer_pub && deobf_peer && strcmp(b->peer_pub, deobf_peer) != 0) changed = true;
            
            if ((b->local_priv == NULL) != (local_priv == NULL)) changed = true;
            if ((b->local_pub == NULL) != (local_pub == NULL)) changed = true;
            if ((b->peer_pub == NULL) != (deobf_peer == NULL)) changed = true;

            if (strcmp(b->local_ip, local_ip ? local_ip : "") != 0) changed = true;
            if (strcmp(b->peer_ip, peer_ip ? peer_ip : "") != 0) changed = true;
            if (strcmp(b->wan_ifname, wan_ifname ? wan_ifname : "") != 0) changed = true;
            if (strcmp(b->key_id, key_id ? key_id : "") != 0) changed = true;
            if (b->role_mode != role_mode) changed = true;

            fprintf(stderr,
                    "[PQC-BIND-DBG] Profile %d: %s config, stopping old worker before clean restart.\n",
                    profile_id, changed ? "changed" : "unchanged");
            stop_rc = pqc_stop_worker_locked(
                b, PQC_WORKER_STOP_TIMEOUT_MS);
            if (stop_rc != 0) {
                fprintf(stderr,
                        "[PQC-BIND] Profile %d worker did not stop cleanly: %s\n",
                        profile_id, strerror(-stop_rc));
                pthread_mutex_unlock(&g_key_mutex);
                free(new_local_priv);
                free(new_local_pub);
                free(deobf_peer);
                return stop_rc;
            }

            pqc_hs_clear_cache_locked(b);
            pqc_flush_rx_queue(b);
            b->key_ready = false;
            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->send_poke = true;
            b->keepalive_enabled = false;
            b->keepalive_monitor_start_time = 0;
            b->last_keepalive_rx_time = 0;
            b->next_auto_retry_time = 0;
            b->keepalive_peer_unreachable = false;
            b->keepalive_rx_last_error = 0;
            b->request_rx_last_error = 0;
            b->hello_rx_last_status = PQC_HS_HELLO_DIAG_OK;
            pqc_key_rotation_init(&b->rotation);
        }
        b->policy_id = profile_id;
        b->profile_id = profile_id;
        b->config_generation = config_generation;
        b->l2_rekey_enabled = l2_rekey_enabled;
        b->role_mode = role_mode;
        // Default assignment for is_initiator based on static roles
        if (role_mode == PQC_ROLE_INITIATOR) {
            b->is_initiator = true;
        } else if (role_mode == PQC_ROLE_RESPONDER) {
            b->is_initiator = false;
        } else {
            b->is_initiator = false; // Will be resolved dynamically
        }
        b->local_request_id = new_request_id;
        b->peer_request_id = 0;
        b->local_keepalive_seq = 0;
        b->peer_keepalive_epoch = 0;
        b->peer_keepalive_seq = 0;
        b->send_poke = role_mode != PQC_ROLE_INITIATOR;
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
        /* Advertise FAILED/HANDSHAKING as well as READY.  This lets a newly
         * rebooted profile wake a peer which is still holding the old key. */
        b->keepalive_enabled = true;
        b->keepalive_monitor_start_time = get_time_ms_hs();
        b->last_keepalive_rx_time = 0;
        b->next_auto_retry_time = 0;
        b->keepalive_peer_unreachable = false;

        if (b->local_priv) free(b->local_priv);
        if (b->local_pub) free(b->local_pub);
        if (b->peer_pub) free(b->peer_pub);

        b->local_priv = new_local_priv;
        b->local_pub = new_local_pub;
        b->peer_pub = deobf_peer;
        new_local_priv = NULL;
        new_local_pub = NULL;
        deobf_peer = NULL;

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

    free(new_local_priv);
    free(new_local_pub);
    free(deobf_peer);
    if (!b)
        return -ENOSPC;
    return 0;
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
                    int stop_rc = pqc_stop_worker_locked(
                        b, PQC_WORKER_STOP_TIMEOUT_MS);
                    if (stop_rc != 0) {
                        fprintf(stderr,
                                "[PQC-RECONCILE] Profile %d worker stop timed out; binding retained until worker exits.\n",
                                b->profile_id);
                        continue;
                    }
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
            pqc_flush_rx_queue(b);
            b->keepalive_enabled = false;
            b->local_request_id = 0;
            b->peer_request_id = 0;
            b->local_keepalive_seq = 0;
            b->peer_keepalive_epoch = 0;
            b->peer_keepalive_seq = 0;
            b->keepalive_monitor_start_time = 0;
            b->last_keepalive_rx_time = 0;
            b->next_auto_retry_time = 0;
            b->keepalive_peer_unreachable = false;
            b->worker_state = PQC_RUNTIME_STOPPED;
            b->worker_last_error = 0;
            b->keepalive_rx_last_error = 0;
            b->request_rx_last_error = 0;
            b->hello_rx_last_status = PQC_HS_HELLO_DIAG_OK;
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

void sig_pqc_trigger_retry(int profile_id) {
    char info[256];
    int rc = sig_pqc_trigger_retry_with_info(profile_id, info, sizeof(info));

    if (rc != 0)
        fprintf(stderr, "[PQC-HS] Manual retry failed: %s\n", info);
}

int sig_pqc_trigger_retry_with_info(int profile_id, char *out_info, size_t out_max) {
    char key_id[256] = {0};
    char wan_ifname[64] = {0};
    char peer_ip[64] = {0};
    uint64_t new_request_id = 0;
    bool is_initiator = false;
    int rc;
    int idx = -1;

    if (!out_info || out_max == 0)
        return -EINVAL;
    rc = pqc_generate_request_id(&new_request_id);
    if (rc != 0) {
        snprintf(out_info, out_max,
                 "Profile %d could not create a handshake request ID: %s",
                 profile_id, strerror(-rc));
        return rc;
    }

    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_policy_bindings_count; i++) {
        if (g_policy_bindings_active[i] &&
            g_policy_bindings[i].profile_id == profile_id) {
            policy_key_binding_t *b = &g_policy_bindings[i];
            int stop_rc;

            if (!b->local_priv || !b->local_pub || !b->peer_pub) {
                pthread_mutex_unlock(&g_key_mutex);
                snprintf(out_info, out_max,
                         "Profile ID %d has an incomplete PQC binding",
                         profile_id);
                return -EINVAL;
            }

            stop_rc = pqc_stop_worker_locked(
                b, PQC_WORKER_STOP_TIMEOUT_MS);
            if (stop_rc != 0) {
                pthread_mutex_unlock(&g_key_mutex);
                snprintf(out_info, out_max,
                         "Profile %d worker did not stop: %s", profile_id,
                         strerror(-stop_rc));
                return stop_rc;
            }

            b->handshake_give_up = false;
            b->handshake_start_time = 0;
            b->key_ready = false;
            b->local_request_id = new_request_id;
            b->local_keepalive_seq = 0;
            b->send_poke = !b->is_initiator;
            b->keepalive_enabled = b->is_tunnel;
            b->keepalive_monitor_start_time = get_time_ms_hs();
            b->last_keepalive_rx_time = 0;
            b->next_auto_retry_time = 0;
            b->keepalive_peer_unreachable = false;
            b->keepalive_rx_last_error = 0;
            b->request_rx_last_error = 0;
            b->hello_rx_last_status = PQC_HS_HELLO_DIAG_OK;
            pqc_hs_clear_cache_locked(b);
            pqc_flush_rx_queue(b);

            snprintf(key_id, sizeof(key_id), "%s", b->key_id);
            snprintf(wan_ifname, sizeof(wan_ifname), "%s", b->wan_ifname);
            snprintf(peer_ip, sizeof(peer_ip), "%s", b->peer_ip);
            is_initiator = b->is_initiator;
            idx = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);

    if (idx < 0) {
        snprintf(out_info, out_max,
                 "Profile ID %d has no active PQC binding in RAM; run -id first",
                 profile_id);
        return -ENOENT;
    }

    rc = sig_pqc_handshake_start(profile_id, wan_ifname, peer_ip);
    if (rc != 0) {
        snprintf(out_info, out_max,
                 "Profile %d retry could not start on %s: %s",
                 profile_id, wan_ifname[0] ? wan_ifname : "<empty>",
                 strerror(-rc));
        fprintf(stderr,
                "[PQC-HS] Manual retry for Profile %d failed to recover runtime: %s\n",
                profile_id, strerror(-rc));
        return rc;
    }

    pthread_mutex_lock(&g_key_mutex);
    const char *state = pqc_runtime_state_name(
        g_policy_bindings[idx].worker_state);
    snprintf(out_info, out_max,
             "Profile=%d KeyID=%s Iface=%s Peer=%s Role=%s Status=%s",
             profile_id, key_id[0] ? key_id : "N/A", wan_ifname, peer_ip,
             is_initiator ? "Initiator" : "Responder", state);
    pthread_mutex_unlock(&g_key_mutex);

    fprintf(stderr,
            "[PQC-HS] Manual retry triggered for Profile %d. Queue/cache flushed and runtime is %s.\n",
            profile_id, state);
    return 0;
}
