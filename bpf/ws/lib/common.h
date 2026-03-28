/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Watershed */

#pragma once


#include "types.h"
#include "defs.h"
#include "maps.h"

enum snat_event_op {
    SNAT_OP_UPDATE,
    SNAT_OP_DELETE,
} snat_event_op;



static __always_inline void print_ipv4_port(const char *label, __u32 addr_host, __u16 port_host)
{
    __u8 a = (addr_host >> 24) & 0xFF;
    __u8 b = (addr_host >> 16) & 0xFF;
    __u8 c = (addr_host >> 8)  & 0xFF;
    __u8 d =  addr_host        & 0xFF;

    bpf_printk("%s | %d.%d.%d.%d:%d\n", label, a, b, c, d, port_host);
}


