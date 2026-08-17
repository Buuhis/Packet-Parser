#ifndef APP_CONTEXT_H
#define APP_CONTEXT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>

#define MAX_SDWAN_TUNS     8
#define MAX_ENCRYPT_KEY_LEN  32  /* AES-256 = 32 bytes */
#define MAX_ENCRYPT_SALT_LEN  4  /* 4 bytes static salt */
#define MAX_TUNNEL_IP_LEN   51
#define MAX_MONITOR_IP_LEN  46

typedef struct {
    char tunnel_ifname[IFNAMSIZ];
    char physical_ifname[IFNAMSIZ];
    char tunnel_ip[MAX_TUNNEL_IP_LEN];
    int  segment_id;
    int  weight;
    char latency_ip[MAX_MONITOR_IP_LEN];
    int  latency;
    bool latency_enabled;
    char loss_ip[MAX_MONITOR_IP_LEN];
    int  loss_percentage;
    bool loss_enabled;
} sdwan_tun_cfg_t;

typedef struct {
    bool     enabled;
    uint8_t  layer;                             /* 2=L2 (MACsec), 3=L3 (Overlay) */
    uint8_t  type;                              /* 0=aes-gcm-128, 1=aes-gcm-256, 2=pqc-gcm */
    uint8_t  key[MAX_ENCRYPT_KEY_LEN];          /* Raw binary key */
    size_t   key_len;                           /* 16 (128-bit) or 32 (256-bit) */
    uint8_t  salt[MAX_ENCRYPT_SALT_LEN];        /* 4 bytes static salt */
} encrypt_cfg_t;

typedef struct {
    int  node_id;

    size_t sdwan_tun_count;
    sdwan_tun_cfg_t sdwan_tuns[MAX_SDWAN_TUNS];

    bool weight_enabled;
    bool latency_enabled;
    bool loss_enabled;
    int latency_duration;
    int loss_duration;

    encrypt_cfg_t encrypt;

} app_config_t;

typedef struct {
    app_config_t cfg;
} app_context_t;

void app_context_dump(const app_context_t *ctx);

#endif
