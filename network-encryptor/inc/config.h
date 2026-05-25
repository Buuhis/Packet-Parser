#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define MAX_BATCH_SIZE  1024

#define CRYPTO_MODE_CTR  0
#define CRYPTO_MODE_GCM  1

// ----- PQC AEAD OPTIONS -----
#define CRYPTO_MODE_PQC_GCM      2  // AES-256-GCM-SIGNET

#define DEFAULT_FRAME_SIZE      4096
#define DEFAULT_BATCH_SIZE      64
#define DEFAULT_UMEM_MB_LOCAL   2048
#define DEFAULT_UMEM_MB_WAN     256
#define DEFAULT_RING_SIZE       262144
#define DEFAULT_RING_SIZE_WAN   32768
#define WAN_REORDER_WINDOW_KB   10240
#define MAX_SRC_NETS 32
#define MAX_DST_NETS 32
#define MAX_REDIRECT_RULES 32
#define DEFAULT_QUEUE_COUNT     1
#define MAX_PROFILES 32
#define MAX_PROFILE_INTERFACES 16
#define MAX_PROFILE_TRAFFIC_RULES 64
#define MAX_CRYPTO_POLICIES 128
#define POLICY_PROTO_ANY 0

enum policy_action {
    POLICY_ACTION_BYPASS = 0,
    POLICY_ACTION_ENCRYPT_L2 = 2,
    POLICY_ACTION_ENCRYPT_L3 = 3,
    POLICY_ACTION_ENCRYPT_L4 = 4
};

struct profile_traffic_rule {
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
};

struct crypto_policy {
    int id;
    int profile_id;
    int db_id;
    int priority;
    int action;
    uint8_t protocol;
    int src_port_from;
    int src_port_to;
    int dst_port_from;
    int dst_port_to;
    int src_any;
    int dst_any;
    int src_negate;
    int dst_negate;
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
    int crypto_mode;
    int aes_bits;
    int nonce_size;
    uint8_t key[AES_KEY_LEN];
    char *identity_priv;
    char *identity_pub;
};

struct profile_config {
    int id;
    char name[64];
    char local_identity_fingerprint[16];
    int enabled;
    int channel_bonding;
    int local_indices[MAX_PROFILE_INTERFACES];
    int local_count;
    int wan_indices[MAX_PROFILE_INTERFACES];
    int wan_bandwidth_weight[MAX_PROFILE_INTERFACES];
    int wan_count;
    struct profile_traffic_rule traffic_rules[MAX_PROFILE_TRAFFIC_RULES];
    int traffic_rule_count;
    int policy_indices[MAX_CRYPTO_POLICIES];
    int policy_count;
};

struct local_config {
    char ifname[IF_NAMESIZE];
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int queue_count;
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint32_t dst_ip;      
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t window_size;
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int queue_count;
};
struct redirect_cfg {
    uint32_t src_net[MAX_SRC_NETS];
    uint32_t src_mask[MAX_SRC_NETS];
    uint32_t src_count;

    uint32_t dst_net[MAX_DST_NETS];
    uint32_t dst_mask[MAX_DST_NETS];
    uint32_t dst_count;
};

struct app_config {
    uint32_t global_frame_size;
    uint32_t global_batch_size;

    struct local_config locals[MAX_INTERFACES];
    int local_count;

    struct wan_config wans[MAX_INTERFACES];
    int wan_count;

    char bpf_file[256];

    int crypto_enabled;
    uint8_t crypto_key[AES_KEY_LEN];
    int encrypt_layer;
    uint16_t fake_ethertype_ipv4;
    uint16_t fake_ethertype_ipv6;
    uint8_t fake_protocol;
    int crypto_mode;
    int nonce_size;
    int aes_bits;
    struct redirect_cfg redirect;
    struct profile_config profiles[MAX_PROFILES];
    int profile_count;
    struct crypto_policy policies[MAX_CRYPTO_POLICIES];
    int policy_count;
};
struct redirect_rule {
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
};

int parse_mac(const char *str, uint8_t *mac);
int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network);
int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len);
int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);
int config_validate(struct app_config *cfg);
int config_select_profile_for_flow(struct app_config *cfg, uint32_t src_ip, uint32_t dst_ip);
int config_select_wan_for_profile(struct app_config *cfg, int profile_idx,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t protocol);
const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol);

#endif