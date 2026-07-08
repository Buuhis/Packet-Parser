#ifndef PQC_HANDSHAKE_H
#define PQC_HANDSHAKE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PQC_HS_PORT        7090
#define PQC_HS_MAGIC       0x50514348 // "PQCH"
#define PQC_HS_MSG_HELLO   1
#define PQC_HS_MSG_RESP    2
#define PQC_HS_MSG_KEEPALIVE 3
#define PQC_HS_MSG_POKE    4

#define PQC_KEM_PK_SIZE    1184 // ML-KEM-768 PK size
#define PQC_KEM_CT_SIZE    1088 // ML-KEM-768 CT size
#define PQC_AUTH_TAG_SZ    32
#define PQC_TRAFFIC_KEY_SZ 32
#define PQC_HS_MSG_MAX_SZ  10000

#ifndef KEY_SLOT_COUNT
#define KEY_SLOT_COUNT   3
#endif

#ifndef KEY_SLOT_PREV
#define KEY_SLOT_PREV    0
#define KEY_SLOT_CURRENT 1
#define KEY_SLOT_NEXT    2
#endif

#define PQC_RX_QUEUE_SIZE  16
#define MAX_IDENTITY_REGISTRY 10
#define MAX_POLICY_BINDINGS 128
#define MAX_L2_DISPATCHERS 16

typedef struct {
    char fingerprint[16];
    char *priv_key;
    char *pub_key;
} identity_entry_t;

typedef struct {
    int policy_id;
    uint8_t diversified_key[PQC_TRAFFIC_KEY_SZ];
    bool valid;
} diversified_key_cache_t;

typedef struct {
    struct sockaddr_in src_addr;
    uint8_t src_mac[6];
} pqc_rx_pkt_info_t;

typedef struct {
    // 8-Byte Aligned Members
    uint64_t last_rotation_time;
    uint64_t last_sent_time;
    uint64_t last_recv_time;
    uint64_t handshake_start_time;
    uint64_t rotation_start_time;

    char *local_priv;
    char *local_pub;
    char *peer_pub;

    pthread_t thread_id;
    uint8_t *rx_queue[PQC_RX_QUEUE_SIZE];
    pthread_mutex_t rx_mutex;
    pthread_cond_t rx_cond;

    // 4-Byte Aligned Members
    int policy_id;
    int profile_id;
    int role_mode;
    int rx_head;
    int rx_tail;
    int rx_len[PQC_RX_QUEUE_SIZE];
    pqc_rx_pkt_info_t rx_info[PQC_RX_QUEUE_SIZE];

    // 1-Byte Aligned Members
    uint8_t encrypt_key[PQC_TRAFFIC_KEY_SZ];
    uint8_t decrypt_key[PQC_TRAFFIC_KEY_SZ];
    uint8_t keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
    uint8_t key_ids[KEY_SLOT_COUNT];
    bool key_slots_valid[KEY_SLOT_COUNT];

    char peer_ip[64];
    char local_fingerprint[16];
    char peer_fingerprint[16];
    char wan_ifname[64];
    char key_id[256];

    bool key_ready;
    bool is_initiator;
    bool thread_started;
    bool handshake_give_up;
    bool rotation_give_up;
    bool send_poke;
    bool is_tunnel;
    volatile bool thread_exit_sig;
} policy_key_binding_t;

typedef struct {
    char ifname[64];
    pthread_t thread;
    bool running;
} l2_dispatcher_t;

#pragma pack(push, 1)
struct pqc_hs_msg {
    uint32_t magic;
    uint8_t  msg_type;
    uint32_t session_id;
    uint32_t policy_id;
    uint16_t sig_len;  // Length of the ML-DSA signature
    uint16_t data_len; // Length of the KEM payload
    uint8_t  payload[0]; // data[data_len] followed by signature[sig_len]
};
#pragma pack(pop)

/**
 * Initializes the underlying Handshake system.
 * @param is_initiator true if this is Server 1 (initiates the Hello message), 
 *                     false if this is Server 2.
 * @param peer_ip The IP address of the peer server.
 * @param identity_priv The local identity private key (used for HMAC signing).
 * @param identity_pub The peer's identity public key (used for HMAC verification).
 */
int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip);

/**
 * Checks whether the Handshake has completed and the key is available.
 * @return true if the handshake is finished and the key is ready, false otherwise.
 */
bool sig_pqc_is_key_ready(void);

/**
 * Retrieves the exchanged traffic key (32 bytes).
 * @param out_key A 32-byte array to store the retrieved key.
 * @return 0 on success, -1 if the key is not yet available.
 */
int sig_pqc_get_traffic_key(uint8_t out_key[PQC_TRAFFIC_KEY_SZ]);

/**
 * Sets the global identity for this system (RAM-only).
 */
void sig_pqc_set_global_identity(const char *priv, const char *pub);

/**
 * Adds an identity keypair to the RAM Registry.
 */
void sig_pqc_add_to_registry(const char *fingerprint, const char *priv, const char *pub);

/**
 * Diversifies the master key of a profile for a specific policy using HMAC-SHA256.
 * @param profile_id The ID of the profile.
 * @param policy_id The ID of the policy to diversify.
 * @param out_policy_key 32-byte array to store the derived policy-specific key.
 * @return 0 on success, -1 if the master key is not ready.
 */
int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key);
#define PQC_USE_DYNAMIC_ROLE  1 // 1 = Dynamic (compare IP/MAC), 0 = Static (DB configured)

typedef enum {
    PQC_ROLE_RESPONDER = 0,
    PQC_ROLE_INITIATOR = 1,
    PQC_ROLE_DYNAMIC   = 2
} pqc_role_mode_t;

bool sig_pqc_has_identity(const char *fingerprint);
void sig_pqc_bind_policy(int policy_id, int profile_id, int role_mode,
                         const char *peer_ip, const char *local_fg,
                         const char *peer_fg, const char *wan_ifname,
                         const char *key_id,
                         const char *local_priv, const char *local_pub,
                         const char *peer_pub, bool is_tunnel);
int sig_pqc_find_identity(const char *fingerprint, char **out_priv, char **out_pub);
void sig_pqc_load_keys_from_disk(void);
char* sig_pqc_deobfuscate_peer_pub(const char *obf_pub_str, const char *peer_fingerprint);

/**
 * Feed a received PQC handshake packet (UDP payload only) into the handshake module.
 * Called by the forwarder WAN RX thread when it detects a UDP packet to port PQC_HS_PORT.
 * @param udp_payload Pointer to the UDP payload (after UDP header).
 * @param payload_len Length of the UDP payload.
 */
void sig_pqc_feed_rx_packet(const uint8_t *payload, int len, const uint8_t *src_mac);

void sig_pqc_record_sent(int policy_id);
void sig_pqc_record_recv(int policy_id);

int sig_pqc_get_keys(int policy_id, uint8_t keys[3][32], uint8_t key_ids[3], bool key_slots_valid[3]);
void sig_pqc_promote_responder_key(int policy_id);
void sig_pqc_discard_prev_key(int policy_id);
void sig_pqc_trigger_retry(int policy_id);
int sig_pqc_trigger_retry_with_info(int policy_id, char *out_info, size_t out_max);

void sig_pqc_prepare_reload(void);
void sig_pqc_finalize_reload(void);

void sig_pqc_load_and_bind_policy(void *conn_ptr, const void *cfg_ptr, int profile_idx, int db_policy_id, int profile_id);

#endif
