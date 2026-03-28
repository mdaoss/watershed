/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once

struct WatershedState {
  __u32 host_pid;
};

struct {
  int (*type)[BPF_MAP_TYPE_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct WatershedState *value;
} ws_state SEC(".maps");
