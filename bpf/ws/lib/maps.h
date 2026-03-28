/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once

#include "linux/vmlinux.h"
#include "common.h"

// These names must match the pinned map names created by Cilium.
// In practice you usually reuse/pin from userspace; keep names in sync

SEC(".maps")
extern struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144); // TODO: make configurable
    __type(key, struct ipv4_ct_tuple);
    __type(value, struct ipv4_nat_entry);
} cilium_snat_v4_ext;

SEC(".maps")
extern struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384); // TODO: make configurable
    __uint(map_flags, 0);       // !REMOVED FLAG BPF_F_NO_PREALLOC
    __type(key, struct egress_gw_policy_key);
    __type(value, struct egress_gw_policy_entry);
} cilium_egress_gateway_policy;

// Map with set of egress IP which is populated via userspace
// Map is using to check  is nat entry has relation to egress IP
SEC(".maps")
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096); // max support egress IP count
    __type(key, __be32);       // egress ip in network byte order
    __type(value, __u8);       // dummy (1)
} egress_ip_set;

/* BPF partitioned ringbuf map  for snat_v4_ext events */
struct map_events_snatext_rbuf_part
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, (1 << 24) /* ??? */);
}   map_events_snatext_part_0 SEC(".maps");

SEC(".maps")
extern struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144); // TODO: make configurable
    __type(key, struct ipv4_ct_tuple);
    __type(value, struct ipv4_nat_entry);
} map_sent_snat_entries;