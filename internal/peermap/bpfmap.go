
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

// Watershed related extension for egressgateway
// for discovery pairs of peers
package peermap

import (
	"errors"

	"github.com/cilium/ebpf"
)

type peerBpfMap struct {
	bpfMap *ebpf.Map
}

func (pbm *peerBpfMap) SetPeer(nodeAddr, peerAddr string) error {
	err := pbm.bpfMap.Put(&nodeAddr, &peerAddr)

	return err
}

func (pbm *peerBpfMap) DeletePeer(nodeAddr string) error {
	err := pbm.bpfMap.Delete(&nodeAddr)

	return err
}

func (pbm *peerBpfMap) GetPeer(nodeAddr string) (string, error) {
	var val string

	err := pbm.bpfMap.Lookup(&nodeAddr, &val)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return "", nil

	}

	return "", err
}

//type Manager struct {
//	Peers  sync.Map
//	client client.Clientset
//}
//
//func NewManager(c client.Clientset) *Manager {
//
//	m := &Manager{
//		Peers:  sync.Map{},
//		client: c,
//	}
//
//	return m
//}
//
//func (m *Manager) parsePeer() {
//	//	policyConfig, error := egressgateway.ParseCEGP()
//
//}
//
