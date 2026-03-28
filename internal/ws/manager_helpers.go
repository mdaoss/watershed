// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"encoding/binary"
	"log/slog"
	"maps"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"watershed/internal/bgp"
)

func ipBytesSetToUint32ListWithNetIP(ipset map[[4]byte]struct{}) ([]net.IP, []uint32) {
	tmpNetIPList := make([]net.IP, 0, len(ipset)) //TODO: Remove magic nummber
	tmpU32IPList := make([]uint32, 0, len(ipset)) //TODO: Remove magic nummber
	for k := range maps.Keys(ipset) {
		IPUint32 := binary.BigEndian.Uint32(k[:])
		if IPUint32 == 0 {
			continue
		}
		// TODO: Check for corner cases  - null egress IP
		tmpNetIPList = append(tmpNetIPList, k[:])
		tmpU32IPList = append(tmpU32IPList, IPUint32)
	}

	return tmpNetIPList, tmpU32IPList
}

func waitBpfObjects(bpfMap *ebpf.Map, loopTimeout time.Duration) {
	var ok bool
	for !ok {
		if bpfMap != nil {
			break
		}
		time.Sleep(loopTimeout)
	}
}

// activateEgressIPs - writes egress ip into allowed list of bpf datapath (sync related)
// also added as /32 route to bgp server to be anounced to upstream  bgp router
func (m *Manager) activateEgressIPs(egressIPList []net.IP, egressIPSet *ebpf.Map, gobgp bgp.GoBGP) {
	for _, ip := range egressIPList {
		var v uint8 = 1 // stub value to as we use bpf map as set
		//TODO: replace with BatchUpdate for better perfomance
		egressIPSet.Update(&ip, &v, ebpf.UpdateNoExist)
		//TODO: More clean creation of  hostroutes
		if err := gobgp.AddHostRoute(context.TODO(), ip.String(), m.listenAddress.String()); err != nil {
			m.logger.Error("unable to add route",
				slog.Any("egressIP", ip),
				slog.Any("nexthop", m.listenAddress.String()),
				slog.Any("error", err),
			)
		}
	}
}

func parseEgressGWMap(egressGWMap *ebpf.Map) (gw, src, egress map[[4]byte]struct{}) {
	//Read All rules
	mapIter := egressGWMap.Iterate()
	//TODO: use constants  for key/val size
	var key [12]byte                                            //  0:4 - lpmtrie related; 4:8 - IPv4 of srcPod; 8:12 - DST Addr
	var value [12]byte                                          // 0:4 - egressIP; 4:8 - IPv4 of GW#1; 8:12 - IPv4 GW#2
	var srcPodIPAddrBytesMap = make(map[[4]byte]struct{}, 1024) //TODO: Remove magic number
	var gwIPAddrBytesMap = make(map[[4]byte]struct{}, 2)
	var egressIPAddrBytesMap = make(map[[4]byte]struct{}, 12) //TODO: Remove magic number

	for mapIter.Next(&key, &value) { // using a nil as stub for pointer of 'key' variable
		srcPodIPAddrBytesMap[[4]byte(key[4:8])] = struct{}{}
		gwIPAddrBytesMap[[4]byte(value[4:8])] = struct{}{}
		gwIPAddrBytesMap[[4]byte(value[8:12])] = struct{}{}
		egressIPAddrBytesMap[[4]byte(value[:4])] = struct{}{}
	}

	return gwIPAddrBytesMap, srcPodIPAddrBytesMap, egressIPAddrBytesMap
}

// enterPassiveMode - clean all stuff related to active (gateway) mode
// and disables bgp peering with upstream routers
func (m *Manager) enterPassiveMode() {
	m.peerAddress = nil
	m.egressIPList = nil
	m.egressIPListUint32 = nil
	time.Sleep(1 * time.Second) //TODO: remove magic number | sleep between active check

	if err := m.gobgp.StopWithCheck(context.TODO()); err != nil {
		m.logger.Error("unable to stop bgp sessions", slog.Any("error", err))
	}
}

// getPeerAddressWithCheck - returns peer adress if it is present map
// if peer adress not found - returns nil(net.IP)
func getPeerAddressWithCheck(gwIPAddrBytesMap map[[4]byte]struct{}, listenAddress net.IP) (peerAddress net.IP) {

	i := 0
	// Using iterator from stdlib to access map keys
	for k := range maps.Keys(gwIPAddrBytesMap) {
		// Ingroing local IP and special NO_GATEWAY value - working only with keys of remote peer(s)
		if k == [4]byte(listenAddress) || k == [4]byte{0, 0, 0, 0} {
			continue
		}

		if i > 1 {
			slog.Warn("more than one peer is available. Hint: check that only two gateways are matched by label selector.")
			break
		}
		peerAddress = k[:] // TODO: Add support for cold nodes with same label
		i++
	}

	return peerAddress
}

// bgpSoftReset - soft resets bgp sessions with all peers
// if any error occured - writes to log
func (m *Manager) bgpSoftReset() {
	err := m.gobgp.SoftResetPeer("all") // TODO: remove magic string | peerName
	if err != nil {
		m.logger.Error(
			"failed to make soft-reset after  AS prepend policy disabling:",
			slog.Any("error", "err"),
		)
	}
}

func (m *Manager) startBGPServer() {
	if err := m.gobgp.StartWithPreCheck(
		context.TODO(),
		m.config.BGPConfig.ASN,
		m.config.BGPConfig.NeighborList,
	); err != nil {
		m.logger.Error("unable to start bgp sessions", slog.Any("error", err))
	}
}
