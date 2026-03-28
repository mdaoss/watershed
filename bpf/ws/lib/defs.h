/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

# pragma once

#include "libbpf/bpf_helpers.h"

# define DEBUG

# define BPF_NAME_LEN 16U
# define MAX_EVENTS  (128)


/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

# define EGRESS_POLICY_MAP cilium_egress_gw_policy_v4
# define EGRESS_POLICY_MAP_SIZE 16384


# define __section_maps			SEC("maps")
# define __section_maps_btf		SEC(".maps")

# define MEM_READ(P)                                                            \
  ({                                                                           \
    typeof(P) val = 0;                                                         \
    bpf_probe_read(&val, sizeof(val), &P);                                     \
    val;                                                                       \
  })
