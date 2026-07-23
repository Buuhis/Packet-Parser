#include "../mwan_steer.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/neighbour.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <net/dst.h>
#include <crypto/aead.h>

unsigned int mwan_handle_encap_l2_pqc(struct sk_buff *skb, struct mwan_tunnel *tun)
{
    struct mwan_config *cfg;
    struct net_device *target_dev = tun->dev;
    struct crypto_aead *tfm;
    struct aead_request *req;
    u8 iv[MWAN_GCM_IV_LEN];
    struct mwan_crypto_hdr *chdr;
    u64 seq;
    int ip_pkt_len, err;
    bool resolved;

    if (unlikely(!target_dev)) {
        return NF_ACCEPT;
    }

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (unlikely(!cfg || !cfg->tfm)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    tfm = cfg->tfm;
    ip_pkt_len = skb->len;
    if (ip_pkt_len <= 0) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    skb = skb_unshare(skb, GFP_ATOMIC);
    if (unlikely(!skb)) {
        rcu_read_unlock();
        return NF_DROP;
    }

    if (skb_is_nonlinear(skb)) {
        if (unlikely(skb_linearize(skb))) {
            struct iphdr *iph = ip_hdr(skb);
            pr_warn_ratelimited("mwan_kmod DBG DROP [skb_linearize]: len=%d, proto=%d\n",
                                ip_pkt_len, iph ? iph->protocol : -1);
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    // Dynamic resolution of gateway MAC for L2 tunnel if ethernet
    if (tun->is_ethernet) {
        resolved = mwan_resolve_gateway_mac(tun, target_dev, tun->gateway_mac);
        if (unlikely(!resolved)) {
            pr_warn_ratelimited("mwan_kmod DBG DROP [gateway_mac]: resolution failed\n");
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    /* Checksum Fix: Ensure fresh, valid L4 checksum (TCP/UDP) for ALL packets before encryption */
    {
        struct iphdr *iph = (struct iphdr *)skb->data;
        if (iph && iph->ihl >= 5 && (skb->len >= (iph->ihl * 4))) {
            u32 ip_hdr_len = iph->ihl * 4;
            if (iph->protocol == IPPROTO_TCP && skb->len >= ip_hdr_len + sizeof(struct tcphdr)) {
                struct tcphdr *th = (struct tcphdr *)(skb->data + ip_hdr_len);
                if (skb->ip_summed == CHECKSUM_PARTIAL) {
                    if (skb_checksum_help(skb)) {
                        pr_warn_ratelimited("mwan_kmod DBG DROP [checksum_help]: len=%d\n", ip_pkt_len);
                        rcu_read_unlock();
                        return NF_DROP;
                    }
                } else {
                    int tcp_len = ntohs(iph->tot_len) - ip_hdr_len;
                    if (tcp_len >= sizeof(struct tcphdr) && skb->len >= ip_hdr_len + tcp_len) {
                        th->check = 0;
                        th->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP,
                                                     skb_checksum(skb, ip_hdr_len, tcp_len, 0));
                    }
                }
                skb->ip_summed = CHECKSUM_NONE;
            } else if (iph->protocol == IPPROTO_UDP && skb->len >= ip_hdr_len + sizeof(struct udphdr)) {
                struct udphdr *uh = (struct udphdr *)(skb->data + ip_hdr_len);
                if (skb->ip_summed == CHECKSUM_PARTIAL) {
                    if (skb_checksum_help(skb)) {
                        rcu_read_unlock();
                        return NF_DROP;
                    }
                } else if (uh->check != 0) {
                    int udp_len = ntohs(iph->tot_len) - ip_hdr_len;
                    if (udp_len >= sizeof(struct udphdr) && skb->len >= ip_hdr_len + udp_len) {
                        uh->check = 0;
                        uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len, IPPROTO_UDP,
                                                     skb_checksum(skb, ip_hdr_len, udp_len, 0));
                        if (uh->check == 0) uh->check = CSUM_MANGLED_0;
                    }
                }
                skb->ip_summed = CHECKSUM_NONE;
            }
        }
    }

    seq = (u64)atomic64_inc_return(&cfg->encrypt_seq);
    memcpy(iv, cfg->encrypt_salt, MWAN_SALT_LEN);
    *(__be64 *)(iv + MWAN_SALT_LEN) = cpu_to_be64(seq);

    // Expand skb headroom/tailroom for Ethernet header + Crypto header + Tag
    if (skb_cow(skb, LL_RESERVED_SPACE(target_dev) + ETH_HLEN + MWAN_CRYPTO_HDR_LEN)) {
        struct iphdr *iph = ip_hdr(skb);
        pr_warn_ratelimited("mwan_kmod DBG DROP [skb_cow]: len=%d, proto=%d\n",
                            ip_pkt_len, iph ? iph->protocol : -1);
        rcu_read_unlock();
        return NF_DROP;
    }
    if (skb_tailroom(skb) < MWAN_GCM_TAG_LEN) {
        if (pskb_expand_head(skb, 0, MWAN_GCM_TAG_LEN, GFP_ATOMIC)) {
            struct iphdr *iph = ip_hdr(skb);
            pr_warn_ratelimited("mwan_kmod DBG DROP [pskb_expand_head]: len=%d, proto=%d\n",
                                ip_pkt_len, iph ? iph->protocol : -1);
            rcu_read_unlock();
            return NF_DROP;
        }
    }

    // Prepend Ethernet + Crypto Header
    skb_push(skb, ETH_HLEN + MWAN_CRYPTO_HDR_LEN);
    skb_reset_mac_header(skb);

    // Write Ethernet Header
    struct ethhdr *eth = eth_hdr(skb);
    if (target_dev->dev_addr)
        ether_addr_copy(eth->h_source, target_dev->dev_addr);
    else
        eth_zero_addr(eth->h_source);
    
    if (tun->is_ethernet)
        ether_addr_copy(eth->h_dest, tun->gateway_mac);
    else
        eth_zero_addr(eth->h_dest);
    eth->h_proto = htons(MWAN_L2_PQC_ETHERTYPE);

    // Write Crypto Header
    chdr = (struct mwan_crypto_hdr *)(skb->data + ETH_HLEN);
    chdr->magic = htons(MWAN_CRYPTO_MAGIC);
    // Store original IP packet length in proto and reserved fields (16-bit value)
    chdr->proto = (ip_pkt_len >> 8) & 0xFF;
    chdr->reserved = ip_pkt_len & 0xFF;
    chdr->seq = cpu_to_be64(seq);

    // Put Tag space at the tail
    skb_put(skb, MWAN_GCM_TAG_LEN);

    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        struct iphdr *iph = (struct iphdr *)(skb->data + ETH_HLEN + MWAN_CRYPTO_HDR_LEN);
        pr_warn_ratelimited("mwan_kmod DBG DROP [aead_alloc]: len=%d, proto=%d\n",
                            ip_pkt_len, iph ? iph->protocol : -1);
        rcu_read_unlock();
        return NF_DROP;
    }

    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], (u8 *)chdr, MWAN_CRYPTO_HDR_LEN); // AAD
        
        nents = skb_to_sgvec(skb, &sg[1], ETH_HLEN + MWAN_CRYPTO_HDR_LEN, ip_pkt_len + MWAN_GCM_TAG_LEN);
        if (unlikely(nents < 0)) {
            struct iphdr *iph = (struct iphdr *)(skb->data + ETH_HLEN + MWAN_CRYPTO_HDR_LEN);
            pr_warn_ratelimited("mwan_kmod DBG DROP [skb_to_sgvec]: len=%d, proto=%d\n",
                                ip_pkt_len, iph ? iph->protocol : -1);
            aead_request_free(req);
            rcu_read_unlock();
            return NF_DROP;
        }

        aead_request_set_crypt(req, sg, sg, ip_pkt_len, iv);
        aead_request_set_ad(req, MWAN_CRYPTO_HDR_LEN);

        err = crypto_aead_encrypt(req);
        aead_request_free(req);
        if (err) {
            struct iphdr *iph = (struct iphdr *)(skb->data + ETH_HLEN + MWAN_CRYPTO_HDR_LEN);
            pr_warn_ratelimited("mwan_kmod DBG DROP [encrypt_err=%d]: len=%d, proto=%d\n",
                                err, ip_pkt_len, iph ? iph->protocol : -1);
            rcu_read_unlock();
            return NF_DROP;
        }

        {
            static int encap_print_count = 0;
            if (encap_print_count < 5) {
                encap_print_count++;
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: ip_pkt_len=%d, seq=%llu\n", encap_print_count, ip_pkt_len, seq);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: key_len=%d, key=%*phN\n", encap_print_count, cfg->encrypt_key_len, cfg->encrypt_key_len, cfg->encrypt_key);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: salt=%*phN\n", encap_print_count, MWAN_SALT_LEN, cfg->encrypt_salt);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: iv=%*phN\n", encap_print_count, MWAN_GCM_IV_LEN, iv);
                pr_info("mwan_kmod DBG [Encap L2 PQC %d]: chdr AAD=%*phN\n", encap_print_count, MWAN_CRYPTO_HDR_LEN, chdr);
            }
        }
    }

    skb->ip_summed = CHECKSUM_NONE;

    if (likely(target_dev->real_num_tx_queues > 1)) {
        u16 cpu_id = smp_processor_id();
        u16 q_idx = cpu_id % target_dev->real_num_tx_queues;
        skb_set_queue_mapping(skb, q_idx);
    }

    skb->dev = target_dev;
    skb->protocol = htons(MWAN_L2_PQC_ETHERTYPE);

    rcu_read_unlock();

    dev_queue_xmit(skb);
    return NF_STOLEN;
}
