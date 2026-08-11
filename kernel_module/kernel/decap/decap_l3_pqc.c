/**
 * decap_l3_pqc.c - L3 PQC Decryption Decapsulation
 *
 * This module handles the RX (inbound) path for L3-layer decryption
 * using AES-GCM with a PQC-derived session key.
 *
 * See encap_l3_pqc.c for the design rationale. The decryption logic
 * is identical to decap_l3.c — cfg->tfm holds the PQC session key.
 *
 * NOTE: The caller (mwan_hook_pre_routing in mwan_steer.c) already
 * bypasses PQC handshake packets (UDP port 7090) before reaching here,
 * so all packets arriving in this function are regular encrypted traffic.
 */

#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

/**
 * mwan_handle_decap_l3_pqc - Decrypt an inbound L3 packet encrypted with
 *                             the PQC-derived AES-GCM session key.
 * @skb:  The inbound packet
 * @tun:  The tunnel (unused here, cfg is fetched via RCU internally)
 *
 * Returns: MWAN_DECAP_CONTINUE on success, NF_ACCEPT/NF_DROP on error.
 *
 * Caller holds rcu_read_lock().
 */
unsigned int mwan_handle_decap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct mwan_config *cfg;
    int ret;

    (void)tun; /* tun unused — cfg is the single config for all tunnels */

    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->tfm)
        return (unsigned int)MWAN_DECAP_CONTINUE;

    ret = mwan_handle_decap_l3(skb, cfg);
    return (unsigned int)ret;
}
