// SPDX-License-Identifier: GPL-2.0
#include "mwan_mtu.h"
#include "mwan_proto.h"

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/overflow.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/icmp.h>

struct mwan_mtu_atomic_stats {
	atomic64_t fits;
	atomic64_t needs_segment;
	atomic64_t oversize;
	atomic64_t invalid;
	atomic64_t frag_needed_attempted;
};

static struct mwan_mtu_atomic_stats mwan_mtu_stats[MWAN_MTU_PROFILE_MAX];

static bool mwan_mtu_profile_valid(enum mwan_mtu_profile profile)
{
	return profile >= MWAN_MTU_PROFILE_BYPASS &&
	       profile < MWAN_MTU_PROFILE_MAX;
}

u32 mwan_mtu_profile_overhead(enum mwan_mtu_profile profile)
{
	switch (profile) {
	case MWAN_MTU_PROFILE_BYPASS:
		return 0;
	case MWAN_MTU_PROFILE_L2_PQC:
		/* Both fields live inside target_dev's Ethernet payload. */
		return MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN;
	default:
		return 0;
	}
}

u32 mwan_mtu_inner_limit_by_mtu(u32 target_mtu,
				 enum mwan_mtu_profile profile)
{
	u32 overhead;

	if (!mwan_mtu_profile_valid(profile))
		return 0;
	overhead = mwan_mtu_profile_overhead(profile);
	if (target_mtu <= overhead)
		return 0;
	return target_mtu - overhead;
}

int mwan_mtu_get_limits(const struct net_device *target_dev,
			enum mwan_mtu_profile profile,
			struct mwan_mtu_limits *limits)
{
	u32 target_mtu;
	u32 overhead;

	if (!target_dev || !limits || !mwan_mtu_profile_valid(profile))
		return -EINVAL;

	target_mtu = READ_ONCE(target_dev->mtu);
	overhead = mwan_mtu_profile_overhead(profile);
	if (!target_mtu || target_mtu <= overhead)
		return -ERANGE;

	limits->target_mtu = target_mtu;
	limits->encapsulation_overhead = overhead;
	limits->max_inner_len = target_mtu - overhead;
	return 0;
}

enum mwan_mtu_result
mwan_mtu_classify_len(u32 inner_len, u32 target_mtu,
		      enum mwan_mtu_profile profile, bool is_gso)
{
	u32 max_inner_len;

	if (!inner_len || !mwan_mtu_profile_valid(profile))
		return MWAN_MTU_INVALID;

	max_inner_len = mwan_mtu_inner_limit_by_mtu(target_mtu, profile);
	if (!max_inner_len)
		return MWAN_MTU_INVALID;

	/* Crypto must never consume an aggregate GSO skb as one wire packet. */
	if (is_gso)
		return MWAN_MTU_NEEDS_SEGMENT;
	if (inner_len > max_inner_len)
		return MWAN_MTU_OVERSIZE;
	return MWAN_MTU_FITS;
}

static void mwan_mtu_record(enum mwan_mtu_profile profile,
			    enum mwan_mtu_result result)
{
	struct mwan_mtu_atomic_stats *stats;

	if (!mwan_mtu_profile_valid(profile))
		return;
	stats = &mwan_mtu_stats[profile];

	switch (result) {
	case MWAN_MTU_FITS:
		atomic64_inc(&stats->fits);
		break;
	case MWAN_MTU_NEEDS_SEGMENT:
		atomic64_inc(&stats->needs_segment);
		break;
	case MWAN_MTU_OVERSIZE:
		atomic64_inc(&stats->oversize);
		break;
	case MWAN_MTU_INVALID:
		atomic64_inc(&stats->invalid);
		break;
	}
}

enum mwan_mtu_result
mwan_mtu_classify_ipv4_skb(const struct sk_buff *skb,
			   const struct net_device *target_dev,
			   enum mwan_mtu_profile profile,
			   struct mwan_mtu_decision *decision)
{
	struct mwan_mtu_decision local = {
		.result = MWAN_MTU_INVALID,
	};
	struct iphdr iph_buf;
	const struct iphdr *iph;
	u32 available;
	u32 inner_len;
	int network_offset;
	int err;

	if (!decision)
		decision = &local;
	else
		memset(decision, 0, sizeof(*decision));
	decision->result = MWAN_MTU_INVALID;

	err = mwan_mtu_get_limits(target_dev, profile, &decision->limits);
	if (err || !skb)
		goto out;

	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || (u32)network_offset > skb->len)
		goto out;

	iph = skb_header_pointer(skb, network_offset, sizeof(iph_buf), &iph_buf);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		goto out;

	decision->ipv4_header_len = iph->ihl * 4;
	inner_len = ntohs(iph->tot_len);
	available = skb->len - network_offset;
	if (inner_len < decision->ipv4_header_len || inner_len > available)
		goto out;

	decision->inner_len = inner_len;
	decision->ip_protocol = iph->protocol;
	decision->is_gso = skb_is_gso(skb);
	decision->ipv4_df = !!(ntohs(iph->frag_off) & IP_DF);
	decision->ipv4_fragment =
		!!(ntohs(iph->frag_off) & (IP_MF | IP_OFFSET));
	decision->result = mwan_mtu_classify_len(
		inner_len, decision->limits.target_mtu, profile,
		decision->is_gso);
out:
	mwan_mtu_record(profile, decision->result);
	return decision->result;
}

u32 mwan_mtu_ipv4_l4_payload_limit(const struct net_device *target_dev,
				   enum mwan_mtu_profile profile,
				   u32 ipv4_header_len,
				   u32 l4_header_len)
{
	struct mwan_mtu_limits limits;
	u32 headers;

	if (ipv4_header_len < sizeof(struct iphdr) || ipv4_header_len > 60 ||
	    (ipv4_header_len & 3) || !l4_header_len)
		return 0;
	if (mwan_mtu_get_limits(target_dev, profile, &limits))
		return 0;
	if (check_add_overflow(ipv4_header_len, l4_header_len, &headers) ||
	    limits.max_inner_len <= headers)
		return 0;
	return limits.max_inner_len - headers;
}

bool mwan_mtu_send_frag_needed(struct sk_buff *skb,
			       enum mwan_mtu_profile profile,
			       const struct mwan_mtu_decision *decision)
{
	if (!skb || !decision || !mwan_mtu_profile_valid(profile) ||
	    decision->result != MWAN_MTU_OVERSIZE ||
	    !decision->limits.max_inner_len)
		return false;

	/* icmp_send() applies the IPv4 rules that suppress invalid ICMP errors. */
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
		  htonl(decision->limits.max_inner_len));
	/* icmp_send() has no return value, so this counts attempts, not packets
	 * guaranteed to have reached the original sender. */
	atomic64_inc(&mwan_mtu_stats[profile].frag_needed_attempted);
	return true;
}

void mwan_mtu_stats_get(enum mwan_mtu_profile profile,
			struct mwan_mtu_stats_snapshot *snapshot)
{
	struct mwan_mtu_atomic_stats *stats;

	if (!snapshot)
		return;
	memset(snapshot, 0, sizeof(*snapshot));
	if (!mwan_mtu_profile_valid(profile))
		return;

	stats = &mwan_mtu_stats[profile];
	snapshot->fits = atomic64_read(&stats->fits);
	snapshot->needs_segment = atomic64_read(&stats->needs_segment);
	snapshot->oversize = atomic64_read(&stats->oversize);
	snapshot->invalid = atomic64_read(&stats->invalid);
	snapshot->frag_needed_attempted =
		atomic64_read(&stats->frag_needed_attempted);
}

void mwan_mtu_stats_reset(enum mwan_mtu_profile profile)
{
	struct mwan_mtu_atomic_stats *stats;

	if (!mwan_mtu_profile_valid(profile))
		return;
	stats = &mwan_mtu_stats[profile];
	atomic64_set(&stats->fits, 0);
	atomic64_set(&stats->needs_segment, 0);
	atomic64_set(&stats->oversize, 0);
	atomic64_set(&stats->invalid, 0);
	atomic64_set(&stats->frag_needed_attempted, 0);
}
