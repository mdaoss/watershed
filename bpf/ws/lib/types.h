/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#include "linux/vmlinux.h"

// 	"cilium_egress_gw_policy_v4", // Egress Gateway rules // lpm_trie
struct egress_gw_policy_key {
	struct bpf_lpm_trie_key_u8 lpm_key;
	__u32 saddr;
	__u32 daddr;
};

struct egress_gw_policy_entry {
	__u32 egress_ip;
	__u32 gateway_ip_a;
	__u32 gateway_ip_b; // part of w_a_ter_shed extension
};



struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

struct nat_entry {
	__u64 created;
	__u64 needs_ct;		/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

struct lb4_reverse_nat {
	__be32 address;
	__be16 port;
} __attribute__((packed));

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct lb4_reverse_nat nat_info;
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};


struct ct_entry {
	__u64 reserved0;	/* unused since v1.16 */
	__u64 backend_id;
	__u64 packets;
	__u64 bytes;
	__u32 lifetime;
	__u16 rx_closing:1,
	      tx_closing:1,
	      reserved1:1,	/* unused since v1.12 */
	      lb_loopback:1,
	      seen_non_syn:1,
	      node_port:1,
	      proxy_redirect:1,	/* Connection is redirected to a proxy */
	      dsr_internal:1,	/* DSR is k8s service related, cluster internal */
	      from_l7lb:1,	/* Connection is originated from an L7 LB proxy */
	      reserved2:1,	/* unused since v1.14 */
	      from_tunnel:1,	/* Connection is over tunnel */
	      reserved3:5;
	__u16 rev_nat_index;
	/* In the kernel ifindex is u32, so we need to check in cilium-agent
	 * that ifindex of a NodePort device is <= MAX(u16).
	 * Unused when HAVE_FIB_INDEX is available.
	 */
	__u16 ifindex;

	/* *x_flags_seen represents the OR of all TCP flags seen for the
	 * transmit/receive direction of this entry.
	 */
	__u8  tx_flags_seen;
	__u8  rx_flags_seen;

	__u32 src_sec_id; /* Used from userspace proxies, do not change offset! */

	/* last_*x_report is a timestamp of the last time a monitor
	 * notification was sent for the transmit/receive direction.
	 */
	__u32 last_tx_report;
	__u32 last_rx_report;
};