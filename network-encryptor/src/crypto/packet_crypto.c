#include "../../inc/packet_crypto.h"
#include "../../inc/config.h"
#include "../../inc/crypto_layer2.h"
#include "../../inc/crypto_layer3.h"
#include "../../inc/crypto_layer4.h"
#include "../../sig_encrypt/inc/traffic_crypto.h"
#include "../../sig_encrypt/inc/crypt.h"
#include "../../sig_encrypt/inc/pqc_handshake.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdatomic.h>

static uint16_t g_fake_ethertype_ipv4 = 0;
static uint16_t g_fake_ethertype_ipv6 = 0;
static __thread uint8_t g_fake_protocol = 99;
static int g_encrypt_layer = 0;

static __thread int g_crypto_mode = 0;
static __thread int g_nonce_size = 12;
static __thread int g_aes_bits = 128;


static __thread uint8_t g_policy_id = 0;

static atomic_uint_fast32_t g_nonce_counter = 0;

static __thread EVP_CIPHER_CTX *tls_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_gcm_enc_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_gcm_dec_ctx = NULL;

static __thread uint8_t tls_cached_key[AES_MAX_KEY_SIZE];
static __thread int tls_key_cached = 0;
static __thread int tls_cached_nonce_len = 0;

static __thread uint8_t tls_dec_cached_key[AES_MAX_KEY_SIZE];
static __thread int tls_dec_key_cached = 0;
static __thread int tls_dec_cached_nonce_len = 0;

static EVP_CIPHER_CTX *get_ctx(void) {
    if (!tls_ctx) {
        tls_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_ctx;
}

static EVP_CIPHER_CTX *get_gcm_enc_ctx(void) {
    if (!tls_gcm_enc_ctx) {
        tls_gcm_enc_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_gcm_enc_ctx;
}

static EVP_CIPHER_CTX *get_gcm_dec_ctx(void) {
    if (!tls_gcm_dec_ctx) {
        tls_gcm_dec_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_gcm_dec_ctx;
}

int packet_crypto_get_tunnel_hdr_size(void) {
    return g_nonce_size + 2;
}

void crypto_write_l3_tunnel_header(uint8_t *buf, const uint8_t *nonce,
                                    int nonce_size, uint8_t policy_id,
                                    uint8_t orig_proto) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = orig_proto;
}

void crypto_read_l3_tunnel_header(const uint8_t *buf, int nonce_size,
                                   uint8_t *nonce_out, uint8_t *proto_flag,
                                   uint8_t *policy_id, uint8_t *orig_proto) {
    memcpy(nonce_out, buf, nonce_size);
    if (proto_flag) *proto_flag = buf[0] >> 7;
    if (policy_id) *policy_id = buf[nonce_size];
    if (orig_proto) *orig_proto = buf[nonce_size + 1];
}

void packet_crypto_set_ethertype(uint16_t fake_ipv4, uint16_t fake_ipv6) {
    g_fake_ethertype_ipv4 = fake_ipv4;
    g_fake_ethertype_ipv6 = fake_ipv6;
}
uint16_t packet_crypto_get_fake_ethertype_ipv4(void) { return g_fake_ethertype_ipv4; }
uint16_t packet_crypto_get_fake_ethertype_ipv6(void) { return g_fake_ethertype_ipv6; }

void packet_crypto_set_encrypt_layer(int layer) { g_encrypt_layer = layer; }

void packet_crypto_set_mode(int mode) { g_crypto_mode = mode; }
int  packet_crypto_get_mode(void) { return g_crypto_mode; }

void packet_crypto_set_nonce_size(int size) { g_nonce_size = size; }
int  packet_crypto_get_nonce_size(void) { return g_nonce_size; }

void packet_crypto_set_aes_bits(int bits) { g_aes_bits = bits; }
int  packet_crypto_get_aes_bits(void) { return g_aes_bits; }

static const EVP_CIPHER *get_ctr_cipher(void) {
    return (g_aes_bits == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
}

static const EVP_CIPHER *get_gcm_cipher(void) {
    return (g_aes_bits == 256) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

static int get_key_size(void) {
    return (g_aes_bits == 256) ? 32 : 16;
}

uint32_t packet_crypto_next_counter(void) {
    return atomic_fetch_add(&g_nonce_counter, 1) & 0x7FFFFFFF;
}

void packet_crypto_reset_counter(void) {
    atomic_store(&g_nonce_counter, 0);
}

static void derive_key(const uint8_t master[AES_MAX_KEY_SIZE],
                       uint64_t epoch,
                       uint8_t out_key[AES_MAX_KEY_SIZE]) {
    int key_size = get_key_size();
    uint8_t epoch_buf[8];
    for (int i = 0; i < 8; i++)
        epoch_buf[i] = (uint8_t)(epoch >> (i * 8));

    unsigned char hmac_out[32];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), master, key_size,
         epoch_buf, sizeof(epoch_buf),
         hmac_out, &hmac_len);

    memcpy(out_key, hmac_out, key_size);
}

// Function to update keys if handshake is ready
static void check_and_update_pqc_key(struct packet_crypto_ctx *ctx) {
    if (ctx && ctx->crypto_mode == CRYPTO_MODE_PQC_GCM) {
        uint8_t keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
        uint8_t key_ids[KEY_SLOT_COUNT];
        bool key_slots_valid[KEY_SLOT_COUNT];
        if (sig_pqc_get_keys(ctx->policy_id, keys, key_ids, key_slots_valid) == 0) {
            bool diff = false;
            for (int s = 0; s < KEY_SLOT_COUNT; s++) {
                if (ctx->key_slots_valid[s] != key_slots_valid[s] ||
                    ctx->key_ids[s] != key_ids[s] ||
                    (key_slots_valid[s] && memcmp(ctx->keys[s], keys[s], PQC_TRAFFIC_KEY_SZ) != 0)) {
                    diff = true;
                    break;
                }
            }
            if (diff) {
                memcpy(ctx->keys, keys, KEY_SLOT_COUNT * PQC_TRAFFIC_KEY_SZ);
                memcpy(ctx->key_ids, key_ids, KEY_SLOT_COUNT);
                memcpy(ctx->key_slots_valid, key_slots_valid, KEY_SLOT_COUNT * sizeof(bool));
                printf("[PQC-DATA] Datapath keys updated from control plane for Policy %d!\n", ctx->policy_id);
                for (int s = 0; s < KEY_SLOT_COUNT; s++) {
                    if (ctx->key_slots_valid[s]) {
                        printf("[PQC-DATA]   Slot %d (ID %d): %02X%02X%02X%02X...\n",
                               s, ctx->key_ids[s], ctx->keys[s][0], ctx->keys[s][1], ctx->keys[s][2], ctx->keys[s][3]);
                    } else {
                        printf("[PQC-DATA]   Slot %d: INVALID\n", s);
                    }
                }
            }
        }
    }
}

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx) {
    check_and_update_pqc_key(ctx);
}

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot) {
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT) return NULL;
    if (ctx->crypto_mode == CRYPTO_MODE_PQC_GCM && !ctx->key_slots_valid[slot]) return NULL;
    return ctx->keys[slot];
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE],
                       int crypto_mode) {
    if (!ctx || !master_key) return -1;

    int key_size = get_key_size();
    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = true;
    ctx->crypto_mode = crypto_mode;

    // ----- PQC HANDSHAKE INTEGRATION -----
    if (ctx->crypto_mode == CRYPTO_MODE_PQC_GCM) {
        static bool pqc_init_done = false;
        if (!pqc_init_done) {
            if (trf_pqc_init_global() != TRF_PQC_OK) return -1;
            fprintf(stderr, "[PQC-INIT] Waiting for Handshake to provide keys...\n");
            pqc_init_done = true;
        }
        ctx->cipher_ctx_enc = scrypt_CipherCtxNew();
        ctx->cipher_ctx_dec = scrypt_CipherCtxNew();
        if (!ctx->cipher_ctx_enc || !ctx->cipher_ctx_dec) {
            return -1;
        }
    } else {
        // LEGACY OPENSSL PATH
        memcpy(ctx->master_key, master_key, key_size);
        derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_PREV]);
        derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_CURRENT]);
        derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_NEXT]);
        ctx->key_slots_valid[KEY_SLOT_PREV] = true;
        ctx->key_slots_valid[KEY_SLOT_CURRENT] = true;
        ctx->key_slots_valid[KEY_SLOT_NEXT] = true;
    }

    packet_crypto_reset_counter();

    if (!get_ctx()) {
        return -1;
    }

    return 0;
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx) {
    if (ctx) {
        memset(ctx->master_key, 0, sizeof(ctx->master_key));
        memset(ctx->keys, 0, sizeof(ctx->keys));
        if (ctx->cipher_ctx_enc) {
            scrypt_CipherCtxFree(ctx->cipher_ctx_enc);
            ctx->cipher_ctx_enc = NULL;
        }
        if (ctx->cipher_ctx_dec) {
            scrypt_CipherCtxFree(ctx->cipher_ctx_dec);
            ctx->cipher_ctx_dec = NULL;
        }
        ctx->initialized = false;
    }

    if (tls_ctx) {
        EVP_CIPHER_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
    if (tls_gcm_enc_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_enc_ctx);
        tls_gcm_enc_ctx = NULL;
    }
    if (tls_gcm_dec_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_dec_ctx);
        tls_gcm_dec_ctx = NULL;
    }

    memset(tls_cached_key, 0, sizeof(tls_cached_key));
    memset(tls_dec_cached_key, 0, sizeof(tls_dec_cached_key));
    tls_key_cached = 0;
    tls_dec_key_cached = 0;
}

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE],
                            const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len) {
    if (len <= 0) return 0;

    EVP_CIPHER_CTX *evp = get_ctx();
    if (!evp) return -1;

    int out_len;

    if (EVP_EncryptInit_ex(evp, get_ctr_cipher(), NULL, key, iv) != 1)
        return -1;

    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1)
        return -1;

    int final_len = 0;
    EVP_EncryptFinal_ex(evp, data + out_len, &final_len);

    return 0;
}

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           uint8_t tag_out[AES128_GCM_TAG_SIZE]) {
    if (__builtin_expect(len <= 0, 0)) return 0;

    EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
    if (__builtin_expect(!evp, 0)) return -1;

    int out_len;
    int key_size = get_key_size();


    int key_changed = !tls_key_cached ||
                      memcmp(tls_cached_key, key, key_size) != 0 ||
                      tls_cached_nonce_len != nonce_len;

    if (__builtin_expect(key_changed, 0)) {

        if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
            return -1;

        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;

        if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1)
            return -1;

        memcpy(tls_cached_key, key, key_size);
        tls_key_cached = 1;
        tls_cached_nonce_len = nonce_len;
    } else {

        if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
            return -1;
    }

    if (__builtin_expect(EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1, 0))
        return -1;

    if (__builtin_expect(EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1, 0))
        return -1;

    if (__builtin_expect(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES128_GCM_TAG_SIZE, tag_out) != 1, 0))
        return -1;

    return 0;
}

int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           const uint8_t tag[AES128_GCM_TAG_SIZE]) {
    if (__builtin_expect(len <= 0, 0)) return 0;

    EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
    if (__builtin_expect(!evp, 0)) return -1;

    int out_len;
    int key_size = get_key_size();


    int key_changed = !tls_dec_key_cached ||
                      memcmp(tls_dec_cached_key, key, key_size) != 0 ||
                      tls_dec_cached_nonce_len != nonce_len;

    if (__builtin_expect(key_changed, 0)) {

        if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
            return -1;

        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;

        if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1)
            return -1;

        memcpy(tls_dec_cached_key, key, key_size);
        tls_dec_key_cached = 1;
        tls_dec_cached_nonce_len = nonce_len;
    } else {

        if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
            return -1;
    }

    if (__builtin_expect(EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1, 0))
        return -1;

    if (__builtin_expect(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES128_GCM_TAG_SIZE,
                                             (void *)tag) != 1, 0))
        return -1;

    if (__builtin_expect(EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1, 0))
        return -1;

    return 0;
}


static __thread uint8_t tls_nonce_salt[16];
static __thread int tls_salt_initialized = 0;

void crypto_generate_nonce(uint32_t counter, uint8_t proto_flag,
                           uint8_t *out_nonce, int *out_nonce_len) {
    const int ns = g_nonce_size;


    out_nonce[0] = (proto_flag << 7) | ((counter >> 24) & 0x7F);
    out_nonce[1] = (counter >> 16) & 0xFF;
    out_nonce[2] = (counter >> 8) & 0xFF;
    out_nonce[3] = counter & 0xFF;


    if (ns > 4) {
        if (__builtin_expect(!tls_salt_initialized, 0)) {
            RAND_bytes(tls_nonce_salt, sizeof(tls_nonce_salt));
            tls_salt_initialized = 1;
        }
        memcpy(out_nonce + 4, tls_nonce_salt, ns - 4);
    }

    if (g_crypto_mode == CRYPTO_MODE_CTR) {
        *out_nonce_len = 16;
    } else {
        *out_nonce_len = ns;
    }
}

void crypto_nonce_to_iv(const uint8_t *nonce, int nonce_size,
                        uint8_t iv[AES128_IV_SIZE]) {
    memcpy(iv, nonce, nonce_size);
    if (nonce_size < AES128_IV_SIZE)
        memset(iv + nonce_size, 0, AES128_IV_SIZE - nonce_size);
}

void crypto_write_counter(uint8_t *packet, const uint8_t *nonce,
                          int nonce_size, uint8_t marker_byte, uint8_t policy_id) {
    packet[12] = marker_byte;
    packet[13] = policy_id;
    memcpy(packet + 14, nonce, nonce_size);
}

void crypto_read_counter(const uint8_t *packet, int nonce_size,
                         uint8_t *nonce_out, uint8_t *policy_id, uint8_t *proto_flag) {
    if (policy_id)
        *policy_id = packet[13];
    memcpy(nonce_out, packet + 14, nonce_size);
    if (proto_flag)
        *proto_flag = nonce_out[0] >> 7;
}

uint16_t crypto_calc_ip_checksum(const uint8_t *ip_hdr, int hdr_len) {
    uint32_t sum = 0;
    for (int i = 0; i < hdr_len; i += 2) {
        uint16_t word = ((uint16_t)ip_hdr[i] << 8);
        if (i + 1 < hdr_len)
            word |= ip_hdr[i + 1];
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t crypto_calc_tcp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *tcp_seg, int tcp_seg_len) {
    if (ip_hdr_len < 20 || tcp_seg_len < 20) return 0;
    uint32_t sum = 0;
    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += (uint16_t)6;
    sum += (uint16_t)(tcp_seg_len & 0xFFFF);
    for (int i = 0; i < tcp_seg_len; i += 2) {
        uint16_t word;
        if (i == 16 && i + 2 <= tcp_seg_len) {
            word = 0;
        } else {
            word = ((uint16_t)tcp_seg[i] << 8);
            if (i + 1 < tcp_seg_len)
                word |= tcp_seg[i + 1];
            else
                word |= 0;
        }
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t crypto_calc_udp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *udp_seg, int udp_seg_len) {
    if (ip_hdr_len < 20 || udp_seg_len < 8) return 0;

    uint16_t udp_len = ((uint16_t)udp_seg[4] << 8) | udp_seg[5];
    if (udp_len < 8) udp_len = 8;
    if (udp_len > (uint16_t)udp_seg_len) udp_len = (uint16_t)udp_seg_len;

    uint32_t sum = 0;
    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += (uint16_t)17;
    sum += (uint16_t)(udp_len & 0xFFFF);

    for (int i = 0; i < (int)udp_len; i += 2) {
        uint16_t word = ((uint16_t)udp_seg[i] << 8);
        if (i + 1 < (int)udp_len)
            word |= udp_seg[i + 1];
        sum += word;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

void crypto_restore_ipv4_header(uint8_t *packet, size_t pkt_len) {
    (void)pkt_len;
    packet[12] = 0x08;
    packet[13] = 0x00;
}

void crypto_restore_ipv6_header(uint8_t *packet, size_t pkt_len) {
    (void)pkt_len;
    packet[12] = 0x86;
    packet[13] = 0xDD;
}

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len) {
    packet_crypto_update_keys(ctx);

    int res = -1;
    switch (g_encrypt_layer) {
    case 2:
        res = crypto_layer2_encrypt(ctx, packet, pkt_len);
        break;
    case 3:
        res = crypto_layer3_encrypt(ctx, packet, pkt_len);
        break;
    case 4:
        res = crypto_layer4_encrypt(ctx, packet, pkt_len);
        break;
    }
    if (res == 0 && ctx) {
        sig_pqc_record_sent(ctx->policy_id);
    }
    return res;
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len) {
    packet_crypto_update_keys(ctx);

    int res = -1;
    switch (g_encrypt_layer) {
    case 2:
        res = crypto_layer2_decrypt(ctx, packet, pkt_len);
        break;
    case 3:
        res = crypto_layer3_decrypt(ctx, packet, pkt_len);
        break;
    case 4:
        res = crypto_layer4_decrypt(ctx, packet, pkt_len);
        break;
    }
    if (res == 0 && ctx) {
        sig_pqc_record_recv(ctx->policy_id);
    }
    return res;
}

void packet_crypto_set_fake_protocol(uint8_t proto) { g_fake_protocol = proto; }
uint8_t packet_crypto_get_fake_protocol(void) { return g_fake_protocol; }

void packet_crypto_set_policy_id(uint8_t policy_id) { g_policy_id = policy_id; }
uint8_t packet_crypto_get_policy_id(void) { return g_policy_id; }