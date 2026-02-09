#include "mwan_proto.h"

#include <string.h>

int mwan_fragment(const uint8_t *ip_data, uint16_t ip_len,
                  uint32_t seq, mwan_frag_t *out_frags)
{
    if (!ip_data || ip_len == 0 || !out_frags)
        return -1;

    if (ip_len <= MWAN_FRAG_THRESHOLD) {
        /* Single fragment — no splitting needed */
        out_frags[0].ip_chunk  = ip_data;
        out_frags[0].chunk_len = ip_len;
        out_frags[0].hdr = (mwan_hdr_t){
            .seq        = seq,
            .frag_idx   = 0,
            .frag_count = 1,
            .total_len  = ip_len,
        };
        return 1;
    }

    /* Need fragmentation */
    uint16_t offset = 0;
    int nfrags = 0;

    while (offset < ip_len && nfrags < MWAN_MAX_FRAGS) {
        uint16_t remain = ip_len - offset;
        uint16_t chunk  = (remain > MWAN_MAX_CHUNK) ? MWAN_MAX_CHUNK : remain;

        out_frags[nfrags].ip_chunk  = ip_data + offset;
        out_frags[nfrags].chunk_len = chunk;
        out_frags[nfrags].hdr = (mwan_hdr_t){
            .seq        = seq,
            .frag_idx   = (uint8_t)nfrags,
            .frag_count = 0,   /* filled below */
            .total_len  = ip_len,
        };

        offset += chunk;
        nfrags++;
    }

    /* Fill frag_count in all fragments */
    for (int i = 0; i < nfrags; i++) {
        out_frags[i].hdr.frag_count = (uint8_t)nfrags;
    }

    return nfrags;
}
