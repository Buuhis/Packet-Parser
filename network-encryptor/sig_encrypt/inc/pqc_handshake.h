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
#define PQC_TRAFFIC_KEY_SZ 32

#pragma pack(push, 1)
struct pqc_hs_msg {
    uint32_t magic;
    uint8_t  msg_type;
    uint32_t session_id;
    uint16_t data_len;
    uint8_t  data[];
};
#pragma pack(pop)

/**
 * Khởi tạo hệ thống Handshake ngầm.
 * @param is_initiator true nếu là Server 1 (người chủ động gửi Hello), false nếu là Server 2.
 * @param peer_ip Địa chỉ IP của Server đối diện.
 */
int sig_pqc_handshake_start(bool is_initiator, const char *peer_ip);

/**
 * Kiểm tra xem Handshake đã hoàn thành và có khóa chưa.
 */
bool sig_pqc_is_key_ready(void);

/**
 * Lấy khóa traffic (32 bytes) đã được trao đổi.
 * @param out_key Mảng 32 bytes để chứa khóa.
 * @return 0 nếu thành công, -1 nếu chưa có khóa.
 */
int sig_pqc_get_traffic_key(uint8_t out_key[PQC_TRAFFIC_KEY_SZ]);

#endif
