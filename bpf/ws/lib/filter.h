/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once

#include "common.h"
#include "stat.h"

static bool __always_inline
relates_to_any_egress_ip(
    const struct ipv4_ct_tuple *snat_key,
    const struct ipv4_nat_entry *snat_val)
{

    // TODO: real source address is redundant  - one entry should be removed after testing
    const __u8 *daddr_match =
        bpf_map_lookup_elem(&egress_ip_set, &(snat_key->daddr));
    if (daddr_match)
    {
        return true;
    };

    const __u8 *to_saddr_match =
        bpf_map_lookup_elem(&egress_ip_set, &(snat_val->to_saddr));
    if (to_saddr_match)
    {
        return true;
    };

    snat_stat_inc(SNAT_STAT_NOT_EGW);
    return false;
}

static bool __always_inline
is_same_nat_rule_already_sent(
    const struct ipv4_ct_tuple *snat_key,
    const struct ipv4_nat_entry *snat_val)
{

    // TODO: real source address is redundant  - one entry should be removed after testing
    const __u8 *daddr_match =
        bpf_map_lookup_elem(&egress_ip_set, &(snat_key->daddr));

    const __u8 *saddr_match =
        bpf_map_lookup_elem(&egress_ip_set, &(snat_key->saddr));

    const __u8 *to_saddr_match =
        bpf_map_lookup_elem(&egress_ip_set, &(snat_val->to_saddr));

    if (!daddr_match && !saddr_match && !to_saddr_match)
    {
        snat_stat_inc(SNAT_STAT_NOT_EGW);
        return false;
    }

    bpf_printk("daddr: %s | saddr: %s | to_saddr: %s\n", snat_key->daddr, snat_key->saddr, snat_val->to_saddr);
    return true;
}