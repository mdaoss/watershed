//go:build ignore

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#include "linux/vmlinux.h"

#include "libbpf/bpf_core_read.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_tracing.h"


#include "ws.h"

#include "lib/license.h"

#include "logsnat.h"


#define SNAT_EXT_MAP_NAME "cilium_snat_v4_"


SEC("fentry/htab_lru_map_update_elem")
int BPF_PROG(bpf_prog_kern_htab_lru_update, struct bpf_map *map, void *key,
             void *value, u64 map_flags) {

     // BPF Level Filter by MAP name
    char map_name[BPF_NAME_LEN];
    // Safely reads the map’s name from kernel memory into a BPF-side buffer.
    bpf_probe_read_kernel_str(map_name, sizeof(map_name), map->name);

    // Efficiently compares the map name against the target (avokes loops, which BPF forbids).
     if  (__builtin_memcmp(map_name, SNAT_EXT_MAP_NAME, sizeof(SNAT_EXT_MAP_NAME)) == 0){
        log_snat_update(map, key, value, SNAT_OP_UPDATE);
        return 0;
       }

  return 0;
}