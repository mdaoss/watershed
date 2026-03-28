// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

// Watershed related extension for egressgateway
// for discovery pairs of peers

package peermap

import "github.com/cilium/ebpf"

const peerMapPath = "/sys/fs/bpf/tc/global/ws_peer_map"

type PeerMap interface {
	SetPeer(nodeAddr, peerAdr string) error
	GetPeer(nodeAddr string) (string, error)
	DeletePeer(nodeAddr string) error
}

func NewPeerMap() (PeerMap, error) {

	bpfMap, err := ebpf.LoadPinnedMap(peerMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, err
	}

	peerMap := &peerBpfMap{
		bpfMap: bpfMap,
	}

	return peerMap, nil
}
