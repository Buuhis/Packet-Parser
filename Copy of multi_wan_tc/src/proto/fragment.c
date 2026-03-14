#define _POSIX_C_SOURCE 200112L
#include "fragment.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

static atomic_uint_fast32_t g_pkt_id_counter = 0;

uint16_t frag_next_pkt_id(void) {
    return (uint16_t)(atomic_fetch_add(&g_pkt_id_counter, 1) & 0xFFFF);
}

void frag_table_init(struct frag_table *ft) {
    memset(ft, 0, sizeof(*ft));
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        pthread_spin_init(&ft->entries[i].lock, PTHREAD_PROCESS_PRIVATE);
    }
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void frag_table_gc(struct frag_table *ft) {
    uint64_t now = get_time_ns();
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        struct frag_entry *entry = &ft->entries[i];
        if (entry->has_frag0 || entry->has_frag1) {
            pthread_spin_lock(&entry->lock);
            if ((entry->has_frag0 || entry->has_frag1) && (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
                entry->has_frag0 = 0;
                entry->has_frag1 = 0;
            }
            pthread_spin_unlock(&entry->lock);
        }
    }
}

/* calc_ip_checksum removed: replaced by cksum_incremental (RFC 1624) */

/*
 * RFC 1624 Incremental Checksum Update.
 * Given old checksum, update it after changing N 16-bit words.
 * old_words[] = original values, new_words[] = replacement values.
 * This avoids re-scanning the entire IP header from scratch.
 *
 * Cost: ~3 additions per changed word vs 10 additions for full 20-byte header.
 */
static inline uint16_t cksum_incremental(uint16_t old_cksum,
                                         const uint16_t *old_words,
                                         const uint16_t *new_words,
                                         int n) {
    uint32_t sum = (uint16_t)~old_cksum;  /* HC' complement */
    for (int i = 0; i < n; i++) {
        sum += (uint16_t)~old_words[i];    /* subtract old */
        sum += new_words[i];               /* add new */
    }
    /* Fold carry */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

static void frag_write_hdr(uint8_t *buf, uint8_t orig_proto, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = orig_proto | FRAG_FLAG_BIT;
    buf[1] = (uint8_t)(pkt_id >> 8);
    buf[2] = (uint8_t)(pkt_id & 0xFF);
    buf[3] = frag_index;
}

static void frag_read_hdr(const uint8_t *buf, uint8_t *orig_proto, uint16_t *pkt_id, uint8_t *frag_index) {
    *orig_proto = buf[0] & ~FRAG_FLAG_BIT;
    *pkt_id = ((uint16_t)buf[1] << 8) | buf[2];
    *frag_index = buf[3];
}

static int build_fragment(const uint8_t *ip_hdr,
                           int ip_hdr_len,
                           uint32_t payload_len,
                           uint8_t orig_proto,
                           uint16_t pkt_id,
                           uint8_t frag_index,
                           uint8_t *out_buf,
                           uint32_t *out_len) {
    int offset = 14; /* Skip 14-byte Ethernet header (written later by caller) */

    /* IP header */
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;

    /* Fragment header */
    frag_write_hdr(out_buf + offset, orig_proto, pkt_id, frag_index);
    offset += FRAG_PLAIN_HDR_SIZE;

    /* ---- Incremental Checksum (RFC 1624) ----
     * Only 2 fields changed: total_length (offset 2-3) and protocol (offset 8-9 word).
     * Instead of recalculating over all 20 bytes, just update the delta. */

    /* Read OLD values from the copied IP header (before modification) */
    uint16_t old_totlen = ((uint16_t)out_buf[14 + 2] << 8) | out_buf[14 + 3];
    uint16_t old_ttl_proto = ((uint16_t)out_buf[14 + 8] << 8) | out_buf[14 + 9];
    uint16_t old_cksum = ((uint16_t)out_buf[14 + 10] << 8) | out_buf[14 + 11];

    /* Write NEW values */
    uint16_t new_totlen = (uint16_t)(ip_hdr_len + FRAG_PLAIN_HDR_SIZE + payload_len);
    out_buf[14 + 2] = (uint8_t)(new_totlen >> 8);
    out_buf[14 + 3] = (uint8_t)(new_totlen & 0xFF);

    out_buf[14 + 9] = FRAG_PROTOCOL;
    uint16_t new_ttl_proto = ((uint16_t)out_buf[14 + 8] << 8) | FRAG_PROTOCOL;

    /* Incremental update: 2 word changes, ~6 additions total */
    uint16_t old_words[2] = { old_totlen, old_ttl_proto };
    uint16_t new_words[2] = { new_totlen, new_ttl_proto };
    uint16_t new_cksum = cksum_incremental(old_cksum, old_words, new_words, 2);

    out_buf[14 + 10] = (uint8_t)(new_cksum >> 8);
    out_buf[14 + 11] = (uint8_t)(new_cksum & 0xFF);

    *out_len = (uint32_t)offset;
    return 0;
}

int frag_split(const uint8_t *pkt_data, uint32_t pkt_len,
               uint8_t *hdr1, uint32_t *hdr1_len, const uint8_t **pay1, uint32_t *pay1_len,
               uint8_t *hdr2, uint32_t *hdr2_len, const uint8_t **pay2, uint32_t *pay2_len) {
    if (pkt_len < 14 + 20)
        return -1;

    const uint8_t *ip_hdr = pkt_data + 14;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;

    if (ether_type == 0x0800) {
        ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20) return -1;
    } else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } else {
        return -1;
    }

    if (pkt_len < (uint32_t)(14 + ip_hdr_len))
        return -1;

    uint8_t orig_proto;
    if (ether_type == 0x0800) {
        orig_proto = ip_hdr[9];
    } else {
        orig_proto = ip_hdr[6];
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    uint32_t half1 = payload_len / 2;
    uint32_t half2 = payload_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    if (build_fragment(ip_hdr, ip_hdr_len,
                       half1, orig_proto,
                       pkt_id, 0,
                       hdr1, hdr1_len) != 0) {
        return -1;
    }
    *pay1 = payload;
    *pay1_len = half1;

    if (build_fragment(ip_hdr, ip_hdr_len,
                       half2, orig_proto,
                       pkt_id, 1,
                       hdr2, hdr2_len) != 0) {
        return -1;
    }
    *pay2 = payload + half1;
    *pay2_len = half2;

    return 0;
}

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index) {
    if (pkt_len < (uint32_t)(14 + 20 + FRAG_PLAIN_HDR_SIZE))
        return 0;

    uint8_t ip_ver = pkt_data[14] >> 4;
    int ip_hdr_len = 0;
    uint8_t ip_proto = 0;

    if (ip_ver == 4) {
        ip_proto = pkt_data[14 + 9];
        ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    } else if (ip_ver == 6) {
        ip_proto = pkt_data[14 + 6];
        ip_hdr_len = 40;
    } else {
        return 0;
    }

    if (ip_proto != FRAG_PROTOCOL)
        return 0;

    int frag_off = 14 + ip_hdr_len;

    if (pkt_len < (uint32_t)(frag_off + FRAG_PLAIN_HDR_SIZE))
        return 0;

    if (!(pkt_data[frag_off] & FRAG_FLAG_BIT))
        return 0;

    uint8_t orig_proto;
    frag_read_hdr(pkt_data + frag_off, &orig_proto, pkt_id, frag_index);
    return 1;
}

int frag_defragment(uint8_t *packet, size_t pkt_len,
                    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (pkt_len < (size_t)(14 + 20 + FRAG_PLAIN_HDR_SIZE))
        return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    int ip_hdr_len;
    int is_ipv4 = 0;

    if (ether_type == 0x0800) {
        is_ipv4 = 1;
    } else if (ether_type == 0x86DD) {
        is_ipv4 = 0;
    } else if (ether_type == MWAN_ETHERTYPE) {
        if ((packet[14] >> 4) == 4) is_ipv4 = 1;
        else is_ipv4 = 0;
    } else {
        return -1;
    }

    if (is_ipv4) {
        if (packet[14 + 9] != FRAG_PROTOCOL) return -1;
        ip_hdr_len = (packet[14] & 0x0F) * 4;
    } else {
        if (packet[14 + 6] != FRAG_PROTOCOL) return -1;
        ip_hdr_len = 40;
    }

    int frag_off = 14 + ip_hdr_len;
    if (pkt_len < (size_t)(frag_off + FRAG_PLAIN_HDR_SIZE))
        return -1;

    uint8_t orig_proto;
    frag_read_hdr(packet + frag_off, &orig_proto, out_pkt_id, out_frag_index);

    /* Remove frag header: move payload over it */
    size_t payload_len = pkt_len - frag_off - FRAG_PLAIN_HDR_SIZE;
    memmove(packet + frag_off, packet + frag_off + FRAG_PLAIN_HDR_SIZE, payload_len);

    /* Restore original protocol */
    if (is_ipv4) {
        /* Read OLD values before modification */
        uint16_t old_totlen_w = ((uint16_t)packet[14 + 2] << 8) | packet[14 + 3];
        uint16_t old_ttl_proto = ((uint16_t)packet[14 + 8] << 8) | packet[14 + 9];
        uint16_t old_cksum = ((uint16_t)packet[14 + 10] << 8) | packet[14 + 11];

        /* Write NEW values */
        packet[14 + 9] = orig_proto;
        uint16_t new_totlen_w = old_totlen_w - FRAG_PLAIN_HDR_SIZE;
        packet[14 + 2] = (uint8_t)(new_totlen_w >> 8);
        packet[14 + 3] = (uint8_t)(new_totlen_w & 0xFF);
        uint16_t new_ttl_proto = ((uint16_t)packet[14 + 8] << 8) | orig_proto;

        /* Incremental checksum update */
        uint16_t old_w[2] = { old_totlen_w, old_ttl_proto };
        uint16_t new_w[2] = { new_totlen_w, new_ttl_proto };
        uint16_t new_cksum = cksum_incremental(old_cksum, old_w, new_w, 2);
        packet[14 + 10] = (uint8_t)(new_cksum >> 8);
        packet[14 + 11] = (uint8_t)(new_cksum & 0xFF);
    } else {
        packet[14 + 6] = orig_proto;
        uint16_t old_paylen = ((uint16_t)packet[14 + 4] << 8) | packet[14 + 5];
        uint16_t new_paylen = old_paylen - FRAG_PLAIN_HDR_SIZE;
        packet[14 + 4] = (uint8_t)(new_paylen >> 8);
        packet[14 + 5] = (uint8_t)(new_paylen & 0xFF);
    }

    return (int)(pkt_len - FRAG_PLAIN_HDR_SIZE);
}

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len) {
    if (pkt_len < 14 + 20)
        return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;
    int is_ipv4 = 0;

    if (ether_type == 0x0800) {
        is_ipv4 = 1;
    } else if (ether_type == 0x86DD) {
        is_ipv4 = 0;
    } else if (ether_type == MWAN_ETHERTYPE) {
        if ((pkt_data[14] >> 4) == 4) is_ipv4 = 1;
        else is_ipv4 = 0;
    } else {
        return -1;
    }

    if (is_ipv4) {
        ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    } else {
        ip_hdr_len = 40;
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len + FRAG_PLAIN_HDR_SIZE;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len - FRAG_PLAIN_HDR_SIZE;

    int idx = pkt_id & (FRAG_TABLE_SIZE - 1);
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();
    
    pthread_spin_lock(&entry->lock);

    // Xử lý timeout nếu có mảnh cũ treo cứng
    if ((entry->has_frag0 || entry->has_frag1) && (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
        entry->has_frag0 = 0;
        entry->has_frag1 = 0;
    }

    // Nếu slot đang chứa pkt_id hiện tại, hoặc đang rỗng thì xài
    if ((entry->has_frag0 || entry->has_frag1) && entry->pkt_id != pkt_id) {
        // Có gói mới chiếm slot => Clear slot ghi đè
        entry->has_frag0 = 0;
        entry->has_frag1 = 0;
    }

    if (!entry->has_frag0 && !entry->has_frag1) {
        entry->pkt_id = pkt_id;
        entry->timestamp_ns = now;
        // Copy Ethernet & IP Header của gói rơi vào trước (có thể là h1 hoặc h2)
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, pkt_data + 14, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        uint8_t orig_proto, ignored_idx;
        uint16_t ignored_id;
        frag_read_hdr(pkt_data + 14 + ip_hdr_len, &orig_proto, &ignored_id, &ignored_idx);
        entry->orig_proto = orig_proto;
    }

    // Lưu mảng theo index tương ứng
    if (frag_index == 0) {
        if (payload_len > sizeof(entry->data0)) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }
        memcpy(entry->data0, payload, payload_len);
        entry->data0_len = payload_len;
        entry->has_frag0 = 1;
    } else if (frag_index == 1) {
        if (payload_len > sizeof(entry->data1)) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }
        memcpy(entry->data1, payload, payload_len);
        entry->data1_len = payload_len;
        entry->has_frag1 = 1;
    } else {
        pthread_spin_unlock(&entry->lock);
        return -1;
    }

    // Xem đủ 2 mảnh chưa?
    if (entry->has_frag0 && entry->has_frag1) {
        uint32_t total_payload = entry->data0_len + entry->data1_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + total_payload;

        if (total_pkt > 4096) {
            entry->has_frag0 = 0;
            entry->has_frag1 = 0;
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        int off = 0;
        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;

        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;

        // Bơm theo đúng thứ tự data0 rồi data1
        memcpy(out_buf + off, entry->data0, entry->data0_len);
        off += entry->data0_len;

        memcpy(out_buf + off, entry->data1, entry->data1_len);
        off += entry->data1_len;

        if (is_ipv4) {
            /* Read OLD values from the stored IP header */
            uint16_t old_totlen_r = ((uint16_t)out_buf[14 + 2] << 8) | out_buf[14 + 3];
            uint16_t old_ttl_proto_r = ((uint16_t)out_buf[14 + 8] << 8) | out_buf[14 + 9];
            uint16_t old_cksum_r = ((uint16_t)out_buf[14 + 10] << 8) | out_buf[14 + 11];

            /* Write NEW values */
            uint16_t new_totlen_r = (uint16_t)(entry->ip_hdr_len + total_payload);
            out_buf[14 + 2] = (uint8_t)(new_totlen_r >> 8);
            out_buf[14 + 3] = (uint8_t)(new_totlen_r & 0xFF);
            
            out_buf[14 + 9] = entry->orig_proto;
            uint16_t new_ttl_proto_r = ((uint16_t)out_buf[14 + 8] << 8) | entry->orig_proto;

            /* Incremental checksum update */
            uint16_t old_wr[2] = { old_totlen_r, old_ttl_proto_r };
            uint16_t new_wr[2] = { new_totlen_r, new_ttl_proto_r };
            uint16_t new_cksum_r = cksum_incremental(old_cksum_r, old_wr, new_wr, 2);
            out_buf[14 + 10] = (uint8_t)(new_cksum_r >> 8);
            out_buf[14 + 11] = (uint8_t)(new_cksum_r & 0xFF);
        } else {
            out_buf[14 + 6] = entry->orig_proto;
            uint16_t ipv6_paylen = (uint16_t)total_payload;
            out_buf[14 + 4] = (uint8_t)(ipv6_paylen >> 8);
            out_buf[14 + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        *out_len = (uint32_t)off;
        
        // Reset slot
        entry->has_frag0 = 0;
        entry->has_frag1 = 0;
        
        pthread_spin_unlock(&entry->lock);
        return 1; // successfully reassembled
    }

    // Thiếu mảnh, chưa đủ
    pthread_spin_unlock(&entry->lock);
    return 0; // successfully stored frag
}
