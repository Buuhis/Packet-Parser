#ifndef PQC_HANDSHAKE_H
#define PQC_HANDSHAKE_H

#include <stdint.h>
#include <stdbool.h>

#define PQC_HS_PORT        7090
#define PQC_HS_MAGIC       0x50514348 // "PQCH"
#define PQC_HS_MSG_HELLO   1
#define PQC_HS_MSG_RESP    2

#define PQC_KEM_PK_SIZE    1184 // ML-KEM-768 PK size
#define PQC_KEM_CT_SIZE    1088 // ML-KEM-768 CT size
#define PQC_AUTH_TAG_SZ    32
#define PQC_TRAFFIC_KEY_SZ 32
#define PQC_HS_MSG_MAX_SZ  4096

#pragma pack(push, 1)
struct pqc_hs_msg {
    uint32_t magic;
    uint8_t  msg_type;
    uint32_t session_id;
    uint8_t  auth_tag[PQC_AUTH_TAG_SZ];
    uint16_t data_len;
    uint8_t  data[];
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
int sig_pqc_handshake_start(bool is_initiator, const char *peer_ip,
                            const char *identity_priv, const char *identity_pub);

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
 * Sets the peer's identity public key (loaded from global DB).
 */
void sig_pqc_set_peer_identity(const char *pub);

/**
 * Adds an identity keypair to the RAM Registry.
 */
void sig_pqc_add_to_registry(const char *fingerprint, const char *priv, const char *pub);

/**
 * Configures the handshake for a specific profile.
 */
void sig_pqc_set_handshake_config(bool is_initiator, const char *peer_ip, const char *local_fingerprint);
bool sig_pqc_has_identity(const char *fingerprint);
void sig_pqc_bind_profile_keys(int profile_id, const char *local_priv, const char *local_pub, const char *peer_pub);
int sig_pqc_get_profile_keys(int profile_id, char **out_local_priv, char **out_local_pub, char **out_peer_pub);
int sig_pqc_find_identity(const char *fingerprint, char **out_priv, char **out_pub);
void sig_pqc_load_keys_from_disk(void);

#endif
