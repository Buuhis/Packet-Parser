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
        if (entry->valid) {
            pthread_spin_lock(&entry->lock);
            if (entry->valid && (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
                entry->valid = 0;
            }
            pthread_spin_unlock(&entry->lock);
        }
    }
}

static uint16_t calc_ip_checksum(const uint8_t *hdr, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t word = ((uint16_t)hdr[i] << 8);
        if (i + 1 < len)
            word |= hdr[i + 1];
        sum += word;
    }
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

static int build_fragment(const uint8_t *eth_hdr,
                           const uint8_t *ip_hdr,
                           int ip_hdr_len,
                           const uint8_t *payload,
                           uint32_t payload_len,
                           uint8_t orig_proto,
                           uint16_t pkt_id,
                           uint8_t frag_index,
                           uint8_t *out_buf,
                           uint32_t *out_len) {
    int offset = 0;

    /* Ethernet header */
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;

    /* IP header */
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;

    /* Fragment header */
    frag_write_hdr(out_buf + offset, orig_proto, pkt_id, frag_index);
    offset += FRAG_PLAIN_HDR_SIZE;

    /* Payload */
    memcpy(out_buf + offset, payload, payload_len);
    offset += payload_len;

    /* Update IP total length */
    uint16_t ip_total = (uint16_t)(ip_hdr_len + FRAG_PLAIN_HDR_SIZE + payload_len);
    out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
    out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

    /* Set protocol to FRAG_PROTOCOL (253) */
    out_buf[14 + 9] = FRAG_PROTOCOL;

    /* Recalculate IP checksum */
    out_buf[14 + 10] = 0;
    out_buf[14 + 11] = 0;
    uint16_t cksum = calc_ip_checksum(out_buf + 14, ip_hdr_len);
    out_buf[14 + 10] = (uint8_t)(cksum >> 8);
    out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

    *out_len = (uint32_t)offset;
    return 0;
}

int frag_split(const uint8_t *pkt_data, uint32_t pkt_len,
               uint8_t *frag1, uint32_t *frag1_len,
               uint8_t *frag2, uint32_t *frag2_len) {
    if (pkt_len < 14 + 20)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
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

    if (build_fragment(eth_hdr, ip_hdr, ip_hdr_len,
                       payload, half1, orig_proto,
                       pkt_id, 0,
                       frag1, frag1_len) != 0) {
        return -1;
    }

    if (build_fragment(eth_hdr, ip_hdr, ip_hdr_len,
                       payload + half1, half2, orig_proto,
                       pkt_id, 1,
                       frag2, frag2_len) != 0) {
        return -1;
    }

    return 0;
}

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index) {
    if (pkt_len < (uint32_t)(14 + 20 + FRAG_PLAIN_HDR_SIZE))
        return 0;

    uint8_t ip_proto = pkt_data[14 + 9];
    if (ip_proto != FRAG_PROTOCOL)
        return 0;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
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

    if (ether_type == 0x0800) {
        if (packet[14 + 9] != FRAG_PROTOCOL) return -1;
        ip_hdr_len = (packet[14] & 0x0F) * 4;
    } else if (ether_type == 0x86DD) {
        if (packet[14 + 6] != FRAG_PROTOCOL) return -1;
        ip_hdr_len = 40;
    } else {
        return -1;
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
    if (ether_type == 0x0800) {
        packet[14 + 9] = orig_proto;
        uint16_t old_totlen = ((uint16_t)packet[14 + 2] << 8) | packet[14 + 3];
        uint16_t new_totlen = old_totlen - FRAG_PLAIN_HDR_SIZE;
        packet[14 + 2] = (uint8_t)(new_totlen >> 8);
        packet[14 + 3] = (uint8_t)(new_totlen & 0xFF);

        packet[14 + 10] = 0;
        packet[14 + 11] = 0;
        uint16_t cksum = calc_ip_checksum(packet + 14, ip_hdr_len);
        packet[14 + 10] = (uint8_t)(cksum >> 8);
        packet[14 + 11] = (uint8_t)(cksum & 0xFF);
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
    if (ether_type == 0x0800) {
        ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    } else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } else {
        return -1;
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len + FRAG_PLAIN_HDR_SIZE;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len - FRAG_PLAIN_HDR_SIZE;

    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();
    
    pthread_spin_lock(&entry->lock);

    if (frag_index == 0) {
        entry->pkt_id = pkt_id;
        entry->data_len = payload_len;
        if (payload_len > sizeof(entry->data)) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }
        memcpy(entry->data, payload, payload_len);
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, pkt_data + 14, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        uint8_t orig_proto, ignored_idx;
        uint16_t ignored_id;
        frag_read_hdr(pkt_data + 14 + ip_hdr_len, &orig_proto, &ignored_id, &ignored_idx);
        
        entry->orig_proto = orig_proto;
        entry->timestamp_ns = now;
        entry->valid = 1;
        pthread_spin_unlock(&entry->lock);
        return 0; // successfully stored frag 0
    }

    if (frag_index == 1) {
        if (!entry->valid || entry->pkt_id != pkt_id) {
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        if ((now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
            entry->valid = 0;
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        uint32_t total_payload = entry->data_len + payload_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + total_payload;

        if (total_pkt > 4096) {
            entry->valid = 0;
            pthread_spin_unlock(&entry->lock);
            return -1;
        }

        int off = 0;

        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;

        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;

        memcpy(out_buf + off, entry->data, entry->data_len);
        off += entry->data_len;

        memcpy(out_buf + off, payload, payload_len);
        off += payload_len;

        if (ether_type == 0x0800) {
            uint16_t ip_total = (uint16_t)(entry->ip_hdr_len + total_payload);
            out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
            out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);
            
            out_buf[14 + 9] = entry->orig_proto;

            out_buf[14 + 10] = 0;
            out_buf[14 + 11] = 0;
            uint16_t cksum = calc_ip_checksum(out_buf + 14, entry->ip_hdr_len);
            out_buf[14 + 10] = (uint8_t)(cksum >> 8);
            out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);
        } else {
            out_buf[14 + 6] = entry->orig_proto;
            uint16_t ipv6_paylen = (uint16_t)total_payload;
            out_buf[14 + 4] = (uint8_t)(ipv6_paylen >> 8);
            out_buf[14 + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        *out_len = (uint32_t)off;
        entry->valid = 0;
        pthread_spin_unlock(&entry->lock);
        return 1; // successfully reassembled
    }

    pthread_spin_unlock(&entry->lock);
    return -1;
}
