// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"time"

	"watershed/internal/link"
)

func (m *Manager) UpdatePeerConfig() {

	// spinlock untill external (cilium) egressGW does not become avilable
	waitBpfObjects(m.bpfObjects.EgressGwV4, time.Millisecond*100)

	for {
		gwIPAddrBytesMap, srcPodIPAddrBytesMap, egressIPAddrBytesMap := parseEgressGWMap(m.bpfObjects.EgressGwV4)

		// Getting Local Src IPv4 address via default gateway
		m.listenAddress, _ = link.GetLocalSrcIP()

		// If local address is found between adresses of gateways - it is active instance
		_, isActive := gwIPAddrBytesMap[[4]byte(m.listenAddress)]
		m.isActive.Store(isActive)

		if !m.isActive.Load() { // TODO: Support node role change
			m.enterPassiveMode()

			// Early exit from loop if not active mode
			continue
		}

		m.startBGPServer()
		// commented due to excessive number of messages //TODO: make it better
		//slog.Info("watershed instance is operating in ACTIVE mode.")

		m.peerAddress = getPeerAddressWithCheck(gwIPAddrBytesMap, m.listenAddress)

		// BGP
		// TODO: ADD SPLIT BRAIN PROTECTION | Partially resolved via fail of BGP announce now, but delay exists
		// Promoting current WS instance to quickly get priority on upstream router
		// TODO: Refactor code to explictily show that there only one peer is possible in gwIPAddrBytesMap
		// and local gw ip is removed above
		if m.peerAddress == nil {
			m.isInitialPeerUpdateDone.Store(false)

			// Execute only once after peer unavailability
			if !m.IsPeerAbsentBefore.Load() {
				m.gobgp.SetFallbackPrependPolicy()
				//TODO: RUN only if state changed
				m.bgpSoftReset()
			}
			m.IsPeerAbsentBefore.Store(true)

		} else {
			m.IsPeerAbsentBefore.Store(false)

			if m.IsLeadershipChanged() || !m.isInitialPeerUpdateDone.Load() {
				switch m.IsLeader() { //TODO: Handle EdgeCase with nil values
				case true:
					m.gobgp.SetLeaderPrependPolicy()
					m.bgpSoftReset()
				case false:
					m.gobgp.SetSlavePrependPolicy()
					m.bgpSoftReset()
				}
			}

			m.isInitialPeerUpdateDone.Store(true)
		}

		m.egressIPList, m.egressIPListUint32 = ipBytesSetToUint32ListWithNetIP(egressIPAddrBytesMap)
		_, m.srcPodIPListUint32 = ipBytesSetToUint32ListWithNetIP(srcPodIPAddrBytesMap)

		m.server.egressIPListUint32 = m.egressIPListUint32
		m.server.srcPodIPListUint32 = m.srcPodIPListUint32

		// activate announcing egress IP as /32  route to upstream  BGP peers
		// adding egressIP to whitelist in ebpf datapath   (sync-only related)
		m.activateEgressIPs(m.egressIPList, m.bpfObjects.EgressIpSet, m.gobgp)
	}
}
