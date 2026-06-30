#ifndef CFM_H
#define CFM_H

#include <stdint.h>

#define ETH_P_ALL 0x0003
#define ETH_P_CFM 0x8902
#define CFM_OPCODE_CCM 1
#define CFM_MULTICAST_MAC "\x01\x80\xC2\x00\x00\x35" // Level 5 Multicast MAC

// ITU-T Y.1731 Opcodes
#define Y1731_OPCODE_LMR 42
#define Y1731_OPCODE_LMM 43
#define Y1731_OPCODE_DMR 46
#define Y1731_OPCODE_DMM 47
#define Y1731_OPCODE_SLR 54
#define Y1731_OPCODE_SLM 55

typedef struct eth_hdr {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;
} __attribute__((packed)) eth_hdr_t;

typedef struct cfm_ccm_hdr {
    uint8_t  md_lvl_version;   // Level 5 = 0xA0 (5 << 5)
    uint8_t  opcode;           // 1 = CCM
    uint8_t  flags;            // 4 = 100ms interval
    uint8_t  first_tlv_offset; // 70 for standard CCM
    uint32_t seq_number;
    uint16_t mep_id;           // Local MEP ID
    uint8_t  maid[48];         // Maintenance Association ID
} __attribute__((packed)) cfm_ccm_hdr_t;

typedef struct cfm_ccm_packet {
    eth_hdr_t     eth;
    cfm_ccm_hdr_t ccm;
    uint8_t            reserved[22];
    uint8_t            end_tlv;      // 0
} __attribute__((packed)) cfm_ccm_packet_t;

// ITU-T Y.1731 Timestamp structure (NTP format: 32-bit seconds, 32-bit nanoseconds)
typedef struct y1731_timestamp {
    uint32_t sec;
    uint32_t nsec;
} __attribute__((packed)) y1731_timestamp_t;

// DMM / DMR PDU Structure
typedef struct y1731_dmm_dmr_hdr {
    uint8_t           md_lvl_version;   // Level 5 = 0xA0 (5 << 5)
    uint8_t           opcode;           // 47 = DMM, 46 = DMR
    uint8_t           flags;            // 0
    uint8_t           first_tlv_offset; // 32
    y1731_timestamp_t tx_timestamp_f;
    y1731_timestamp_t rx_timestamp_f;
    y1731_timestamp_t tx_timestamp_b;
    y1731_timestamp_t rx_timestamp_b;
} __attribute__((packed)) y1731_dmm_dmr_hdr_t;

typedef struct y1731_dmm_dmr_packet {
    eth_hdr_t           eth;
    y1731_dmm_dmr_hdr_t dmm_dmr;
    uint8_t             end_tlv; // 0
} __attribute__((packed)) y1731_dmm_dmr_packet_t;

// LMM / LMR PDU Structure
typedef struct y1731_lmm_lmr_hdr {
    uint8_t  md_lvl_version;   // Level 5 = 0xA0
    uint8_t  opcode;           // 43 = LMM, 42 = LMR
    uint8_t  flags;            // 0
    uint8_t  first_tlv_offset; // 12
    uint32_t tx_fc_f;          // Transmit Forward Counter
    uint32_t rx_fc_f;          // Receive Forward Counter
    uint32_t tx_fc_b;          // Transmit Backward Counter
} __attribute__((packed)) y1731_lmm_lmr_hdr_t;

typedef struct y1731_lmm_lmr_packet {
    eth_hdr_t           eth;
    y1731_lmm_lmr_hdr_t lmm_lmr;
    uint8_t             end_tlv; // 0
} __attribute__((packed)) y1731_lmm_lmr_packet_t;

// SLM / SLR PDU Structure
typedef struct y1731_slm_slr_hdr {
    uint8_t  md_lvl_version;   // Level 5 = 0xA0
    uint8_t  opcode;           // 55 = SLM, 54 = SLR
    uint8_t  flags;            // 0
    uint8_t  first_tlv_offset; // 16
    uint16_t src_mep_id;
    uint16_t responder_mep_id;
    uint32_t test_id;
    uint32_t tx_fc_l;          // Transmit Forward counter Local
    uint32_t tx_fc_b;          // Transmit Forward counter Backward
} __attribute__((packed)) y1731_slm_slr_hdr_t;

typedef struct y1731_slm_slr_packet {
    eth_hdr_t           eth;
    y1731_slm_slr_hdr_t slm_slr;
    uint8_t             end_tlv; // 0
} __attribute__((packed)) y1731_slm_slr_packet_t;

#endif // CFM_H
