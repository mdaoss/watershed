/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once

#include "linux/vmlinux.h"

#include "libbpf/bpf_core_read.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_endian.h"

#include "lib/common.h"
#include "lib/filter.h"
#include "lib/maps.h"
#include "lib/stat.h"

struct snatExtMapData
{
  struct ipv4_ct_tuple key;     // 112 bit
  struct ipv4_nat_entry value;  // 320 bit
} __attribute__((packed));

static void __always_inline log_snat_update(struct bpf_map *updated_map,
                                            struct ipv4_ct_tuple *pKey,
                                            struct ipv4_nat_entry *pValue,
                                            enum snat_event_op update_type)
{
  snat_stat_inc(SNAT_STAT_ATTEMPT);
  __u32 ws_state_key = 0;

  __u32 host_pid = 0;
  __u32 current_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

  struct WatershedState *state =
  bpf_map_lookup_elem(&ws_state, &ws_state_key);
  if (state){
    host_pid = state->host_pid;
  }

  // Skip events originating from our own process to avoid a sync feedback loop
  if (current_pid == host_pid) {
    snat_stat_inc(SNAT_STAT_PID_REJECTED);
    return;
  };

  /* Copy arguments into stack locals so the verifier sees bounded, safe memory */
  struct ipv4_ct_tuple keyData = {};
  bpf_probe_read(&keyData, sizeof(keyData), pKey);

  struct ipv4_nat_entry valData = {};
  if (pValue)
    bpf_probe_read(&valData, sizeof(valData), pValue);

  struct snatExtMapData *out_data;
  out_data = bpf_ringbuf_reserve(&map_events_snatext_part_0, sizeof(*out_data), 0);


  if (!out_data)
  {
    snat_stat_inc(SNAT_STAT_RESERVE_FAIL);
    return;
  }

  bpf_probe_read(&out_data->key, sizeof(*pKey), pKey);
  if (pValue != 0)
  {
    bpf_probe_read(&out_data->value, sizeof(*pValue), pValue);
  }

  // filtration by egress IP
  bool related_to_egress_policy = relates_to_any_egress_ip(&keyData, &valData);
  if (!related_to_egress_policy)
  {
    bpf_ringbuf_discard(out_data, 0);
    snat_stat_inc(SNAT_STAT_DISCARD);
    return;
  };

//__u32 daddr = bpf_ntohl(keyData.daddr);
//__u16 dport = bpf_ntohl(keyData.dport);
//__u32 saddr = bpf_ntohl(keyData.saddr);
//__u16 sport = bpf_ntohs(keyData.sport);

//__u32 to_saddr = 0;
//__u16 to_sport = 0;
//if (pValue)
//{
//  to_saddr = bpf_ntohl(valData.to_saddr);
//  to_sport = bpf_ntohs(valData.to_sport);
//}

//print_ipv4_port("snat: src", saddr, sport);
//print_ipv4_port("dst", daddr, dport);
//print_ipv4_port("to", to_saddr, to_sport);

  bpf_ringbuf_submit(out_data, BPF_RB_FORCE_WAKEUP);
  snat_stat_inc(SNAT_STAT_SUBMIT);
  return;
}
