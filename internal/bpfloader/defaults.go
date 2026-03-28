// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bpfloader

var watchedEBPFMaps = map[uint32]MapInfo{
	uint32(SNAT_V4_EXTERNAL): {
		Name:    Cilium_snat_v4_external_map_name,
		KeySize: 14,
		ValSize: 40},
	uint32(EGRESS_GW_POLICY_V4): {
		Name:    Cilium_egress_gw_policy_v4_map_name,
		KeySize: 12,
		ValSize: 12},
}

type MapInfo struct {
	Name    BpfMapName
	KeySize int
	ValSize int
}
