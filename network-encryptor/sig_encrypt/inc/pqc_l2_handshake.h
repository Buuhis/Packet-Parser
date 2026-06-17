#ifndef PQC_L2_HANDSHAKE_H
#define PQC_L2_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "types.h" // For SCryptCipherCtx, byte, etc.

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_ETH_TYPE_DISCOVERY 0x88B5
#define PQC_ETH_TYPE_HANDSHAKE 0x88B6
#define PQC_L2_MAGIC           0x5051 // "PQ" in hex

#define PQC_MAX_FRAG_SIZE      1400
#define PQC_L2_TIMEOUT_MS      2000

// Handshake L2 Message Types
enum pqc_l2_msg_type {
    PQC_MSG_DISCOVERY_PROBE = 1,
    PQC_MSG_DISCOVERY_ACK   = 2,
    PQC_MSG_HANDSHAKE_DATA  = 3,
};

// 1. Custom L2 Header (Placed right after the Ethernet Header)
struct pqc_l2_hdr {
    uint16_t magic;         // 0x5051
    uint8_t  msg_type;      // enum pqc_l2_msg_type
    uint8_t  reserved[3];   // Alignment padding
} __attribute__((packed));

// 2. Custom Fragmentation Header (Placed right after pqc_l2_hdr if MSG_HANDSHAKE_DATA)
struct pqc_frag_hdr {
    uint32_t msg_id;        // Unique ID identifying this handshake run
    uint32_t total_len;     // Total size of the unfragmented handshake payload
    uint16_t frag_count;    // Total number of segments
    uint16_t frag_index;    // Index of the current segment (0-based)
    uint16_t payload_len;   // Byte length of data in this fragment
} __attribute__((packed));

// 3. Reassembly state buffer
struct pqc_l2_reassemble {
    uint8_t  *data_buffer;
    uint8_t  *frag_bitmap;  // Bitmap to prevent duplicate fragment processing
    uint64_t start_time_ms; // Timestamp to handle drop timeout
    struct pqc_l2_reassemble* next; // Linked list pointer for active assemblies
    uint32_t msg_id;
    uint32_t total_len;
    uint16_t frag_received;
    uint16_t frag_count;
};

// Peer node MAC state
struct pqc_l2_peer {
    uint8_t  peer_mac[6];
    uint8_t  local_mac[6];
    char     ifname[32];
    int      raw_sock_fd;
    int      discovered;
};

// --- PURE L2 HANDSHAKE CONTROLLER APIs ---

/**
 * Initialize the L2 Peer state and bind a Raw Socket to the specified WAN interface.
 * Returns 0 on success, negative on error.
 */
int pqc_l2_init_peer(struct pqc_l2_peer *peer, const char *ifname);

/**
 * Execute L2 peer discovery: Broadcast a probe and block until an ACK is received.
 * Populates peer->peer_mac upon successful reply.
 * Returns 0 on success, negative on timeout or error.
 */
int pqc_l2_discover_peer_mac(struct pqc_l2_peer *peer, int timeout_sec);

/**
 * Segment a handshake message and transmit it as unicast L2 frames.
 * Returns 0 on success, negative on error.
 */
int pqc_l2_send_payload_fragmented(struct pqc_l2_peer *peer, uint32_t msg_id, 
                                   const uint8_t *payload, uint32_t payload_len);

/**
 * Listen and process incoming raw L2 frames.
 * Handles discovery probes, ACKs, and processes/reassembles handshake fragments.
 * If a complete message is successfully reassembled, 'out_payload' is allocated and returned.
 * Returns length of reassembled payload on success, 0 if still waiting, negative on error.
 */
int pqc_l2_recv_and_process(struct pqc_l2_peer *peer, uint8_t **out_payload, uint32_t *out_msg_id);

/**
 * Cleanup allocated memory and sockets.
 */
void pqc_l2_cleanup_peer(struct pqc_l2_peer *peer);

struct app_config;
/**
 * Dynamically select the best WAN interface for handshake on a given profile.
 * Returns WAN index on success, negative on error.
 */
int pqc_select_handshake_wan(const struct app_config *cfg, int profile_idx);

/**
 * Retrieve the WAN IP and Interface name for handshaking on a profile.
 */
void pqc_get_profile_handshake_params(const struct app_config *cfg, int profile_idx, char *out_peer_ip, const char **out_wan_ifname);

/**
 * Run handshake initialization across all configured profiles.
 */
void pqc_handshake_start_all_profiles(struct app_config *cfg);

#ifdef __cplusplus
}
#endif

#endif // PQC_L2_HANDSHAKE_H
