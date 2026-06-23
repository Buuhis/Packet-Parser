#ifndef CFM_H
#define CFM_H

#include <stdint.h>

#define ETH_P_CFM 0x8902
#define CFM_OPCODE_CCM 1
#define CFM_MULTICAST_MAC "\x01\x80\xC2\x00\x00\x35" // Level 5 Multicast MAC

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

#endif // CFM_H
