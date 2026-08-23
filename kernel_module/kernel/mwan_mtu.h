/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MWAN_MTU_H
#define MWAN_MTU_H

#include <linux/types.h>

struct net_device;
struct sk_buff;

/*
 * target_dev->mtu is the L3 payload MTU advertised by the selected netdev.
 * In particular, a correctly configured VXLAN device has already deducted
 * its outer IP/UDP/VXLAN overhead from the lower device MTU. Do not deduct
 * the VXLAN overhead again here.
 */
enum mwan_mtu_profile {
	MWAN_MTU_PROFILE_BYPASS = 0,
	MWAN_MTU_PROFILE_L2_PQC,
	MWAN_MTU_PROFILE_MAX,
};

enum mwan_mtu_result {
	MWAN_MTU_FITS = 0,
	MWAN_MTU_NEEDS_SEGMENT,
	MWAN_MTU_OVERSIZE,
	MWAN_MTU_INVALID,
};

struct mwan_mtu_limits {
	u32 target_mtu;
	u32 encapsulation_overhead;
	u32 max_inner_len;
};

struct mwan_mtu_decision {
	enum mwan_mtu_result result;
	struct mwan_mtu_limits limits;
	u32 inner_len;
	u16 ipv4_header_len;
	u8 ip_protocol;
	bool is_gso;
	bool ipv4_df;
	bool ipv4_fragment;
};

struct mwan_mtu_stats_snapshot {
	u64 fits;
	u64 needs_segment;
	u64 oversize;
	u64 invalid;
	u64 frag_needed_attempted;
};

u32 mwan_mtu_profile_overhead(enum mwan_mtu_profile profile);
u32 mwan_mtu_inner_limit_by_mtu(u32 target_mtu,
				enum mwan_mtu_profile profile);
int mwan_mtu_get_limits(const struct net_device *target_dev,
			enum mwan_mtu_profile profile,
			struct mwan_mtu_limits *limits);

/* Pure length classifier, suitable for small unit tests. */
enum mwan_mtu_result
mwan_mtu_classify_len(u32 inner_len, u32 target_mtu,
		      enum mwan_mtu_profile profile, bool is_gso);

/*
 * Inspect an IPv4 skb without pulling or modifying it. A GSO skb returns
 * MWAN_MTU_NEEDS_SEGMENT; each produced segment must be classified again.
 */
enum mwan_mtu_result
mwan_mtu_classify_ipv4_skb(const struct sk_buff *skb,
			   const struct net_device *target_dev,
			   enum mwan_mtu_profile profile,
			   struct mwan_mtu_decision *decision);

u32 mwan_mtu_ipv4_l4_payload_limit(const struct net_device *target_dev,
				   enum mwan_mtu_profile profile,
				   u32 ipv4_header_len,
				   u32 l4_header_len);

/*
 * Send ICMP Destination Unreachable / Fragmentation Needed for an oversize
 * original IPv4 skb. This is intentionally separate from classification so
 * the datapath can exempt control traffic or apply a different drop policy.
 */
bool mwan_mtu_send_frag_needed(struct sk_buff *skb,
			       enum mwan_mtu_profile profile,
			       const struct mwan_mtu_decision *decision);

void mwan_mtu_stats_get(enum mwan_mtu_profile profile,
			struct mwan_mtu_stats_snapshot *snapshot);
void mwan_mtu_stats_reset(enum mwan_mtu_profile profile);

#endif /* MWAN_MTU_H */
