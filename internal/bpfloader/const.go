// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bpfloader

// const cilium_egress_gw_policy_v4 = "cilium_egress_gw_policy_v4"
const cilium_egress_gw_policy_v4_pin_path = "/sys/fs/bpf/tc/globals/cilium_egress_gw_policy_v4"
const Cilium_egress_gw_policy_v4_map_name BpfMapName = "cilium_egress_g"
const WS_state_map_name BpfMapName = "ws_state"

// const cilium_snat_v4_external = "cilium_snat_v4_external"
const cilium_snat_v4_external_pin_path = "/sys/fs/bpf/tc/globals/cilium_snat_v4_external"
const Cilium_snat_v4_external_map_name BpfMapName = "cilium_snat_v4_"
const cilium_snat_v4_external_key_size = 14
const cilium_snat_v4_external_val_size = 40

type BpfMapType uint8
type BpfMapName string

const (
	_                           = iota // ignore first value by assigning to blank identifier
	SNAT_V4_EXTERNAL BpfMapType = iota
	EGRESS_GW_POLICY_V4
	ws_state
)

const BpfPinPath = "/sys/fs/bpf/tc/globals"
