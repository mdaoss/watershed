// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package prober

import "net"

type EventKind uint8

const (
	_ EventKind = iota
	GatewayFailed
	GatewayAvailable
	BGPFailure
)

type Event struct {
	Kind        EventKind
	GatewayAddr net.IP
}

func (e *Event) Done() {
}
