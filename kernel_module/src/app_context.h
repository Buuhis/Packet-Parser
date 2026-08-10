#ifndef APP_CONTEXT_H
#define APP_CONTEXT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_WANS           8
#define MAX_SDWAN_TUNS     8
#define MAX_ENCRYPT_KEY_LEN  32  /* AES-256 = 32 bytes */
#define MAX_ENCRYPT_SALT_LEN  4  /* 4 bytes static salt */

typedef struct {
    char name[16];
    char ifname[16];
    char gateway[32];
    int  weight;
    unsigned char dst_mac[6];
} wan_cfg_t;

typedef struct {
    char ifname[16];
    char gateway[32];
    int  port;
    int  weight;
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

    char local_if[16];
    unsigned int local_ip;   /* Network byte order */
    unsigned int local_mask; /* Network byte order */

    size_t wan_count;
    wan_cfg_t wans[MAX_WANS];

    size_t sdwan_tun_count;
    sdwan_tun_cfg_t sdwan_tuns[MAX_SDWAN_TUNS];

    encrypt_cfg_t encrypt;

} app_config_t;

typedef struct {
    app_config_t cfg;
} app_context_t;

void app_context_dump(const app_context_t *ctx);

#endif

