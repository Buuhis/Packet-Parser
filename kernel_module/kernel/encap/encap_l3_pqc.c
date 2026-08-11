/**
 * encap_l3_pqc.c - L3 PQC Encryption Encapsulation
 *
 * This module handles the TX (outbound) path for L3-layer encryption
 * using AES-GCM with a session key derived from the PQC handshake
 * (ML-KEM + ML-DSA) instead of a static pre-shared key from the database.
 *
 * Design decision: The datapath is IDENTICAL to encap_l3.c (AES-GCM).
 * The only difference is HOW the key reaches cfg->tfm:
 *   - MWAN_ENCAP_L3_CUSTOM: key comes from DB (static, user-configured)
 *   - MWAN_ENCAP_L3_PQC:    key comes from PQC handshake (dynamic, ephemeral)
 *
 * After a successful PQC handshake, userspace calls kernel_sync_push_config()
 * which pushes the new session key via Generic Netlink. mwan_state_update()
 * then rebuilds cfg->tfm from that PQC-derived key. From that point on,
 * mwan_handle_encap_l3() uses the PQC session key transparently.
 *
 * Therefore, this function simply delegates to mwan_handle_encap_l3().
 */

#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

/**
 * mwan_handle_encap_l3_pqc - Encrypt and encapsulate an outbound L3 packet
 *                             using the PQC-derived AES-GCM session key.
 * @skb:  The outbound packet
 * @tun:  The selected WAN tunnel
 *
 * Delegates to mwan_handle_encap_l3() which reads cfg->tfm — already
 * provisioned with the PQC session key via Netlink after handshake.
 *
 * Returns: NF_STOLEN on success (packet transmitted), NF_ACCEPT on error.
 */
unsigned int mwan_handle_encap_l3_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    return mwan_handle_encap_l3(skb, tun);
}
