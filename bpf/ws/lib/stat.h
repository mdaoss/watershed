/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once

#include "linux/vmlinux.h"
#include "common.h"



#define SNAT_STAT_ATTEMPT 0
#define SNAT_STAT_PID_REJECTED 1
#define SNAT_STAT_RESERVE_FAIL 2
#define SNAT_STAT_SUBMIT 3
#define SNAT_STAT_DISCARD 4
#define SNAT_STAT_NOT_EGW 5

// Stats map for snat
SEC(".maps")
struct {

    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key,  __u32);
    __type(value, __u64);
} snat_events_stat;



static __always_inline void  snat_stat_inc(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&snat_events_stat, &idx);
    
    if (v) __sync_fetch_and_add(v,1);
}
