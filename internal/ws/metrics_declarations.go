// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ws_egressmap_max_entries_count = *prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ws_egressmap_max_entries_count",
			Help: "Maximum entries count allowed in egressmap",
		},
		[]string{},
	)
	ws_egressmap_curr_entries_count = *prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ws_egressmap_curr_entries_count",
			Help: "Current entries count in egressmap",
		},
		[]string{},
	)
)

func (msrv *SloGazer) egressmapMetricsUpdate() {
	ws_egressmap_curr_entries_count.Reset()
	ws_egressmap_max_entries_count.Reset()

	//Read All rules
	egwpMap := msrv.bpfObjects.EgressGwV4
	if egwpMap == nil {
		slog.Error("unable to access cilium_egress_gw_policy_v4_map ebpf map")
		return
	}

	mapInfo, err := egwpMap.Info()
	if err != nil {
		slog.Error("unable to get map info  for cilium_egress_gw_policy_v4_map ebpf map")
		return
	}
	maxEntriesCount := mapInfo.MaxEntries

	currEntriesCount := 0
	key := [12]byte{} // TODO:  define key/val size via constants
	val := [12]byte{}
	iter := egwpMap.Iterate()
	for iter.Next(&key, &val) {
		currEntriesCount++
	}

	labels := prometheus.Labels{}
	ws_egressmap_curr_entries_count.With(labels).Set(float64(currEntriesCount))
	ws_egressmap_max_entries_count.With(labels).Set(float64(maxEntriesCount))

}
