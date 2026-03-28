// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package prober

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"watershed/internal/config"
)

type addressStatus struct {
	Available       bool
	LastColdStartTS time.Time
}

// Watchdog cheks availability  of gateways and related stuff like BGP Advertisements
type Watchdog struct {
	events chan Event
	//addresses map[[4]byte]addressStatus // SET // BigEndian // TODO: use netip.Addr ???
	addresses     sync.Map // SET // BigEndian // TODO: use netip.Addr ???
	probePort     uint16
	probeInterval time.Duration
}

func NewWatchdog(c *config.Config, l *slog.Logger) *Watchdog {
	watchdog := Watchdog{
		events:        make(chan Event, 16), //TODO: Remove magic number
		addresses:     sync.Map{},
		probePort:     c.PeerPort,
		probeInterval: c.TcpProbeInterval,
	}

	go watchdog.watch()

	l.Debug("started new watchdog:", slog.Any("watchdog", watchdog))

	return &watchdog

}

// Events return prober's internal channel with read-only access
// |  TODO:  Add ctx and rate limiter ???
func (wd *Watchdog) Events() <-chan Event {
	return wd.events
}

func (wd *Watchdog) AddIPv4ToWatchList(ip [4]byte) {
	wd.addresses.Store(ip, addressStatus{Available: false, LastColdStartTS: time.Unix(0, 0)})
}

func (wd *Watchdog) RemoveIPv4FromWatchList(ip [4]byte) {
	wd.addresses.Delete(ip)
}

func (wd *Watchdog) SetProbePort(port uint16) {
	wd.probePort = port
}

func (wd *Watchdog) watch() {
	for {
		ips := make([][4]byte, 0, 2) // 2 - cause of 2 peers
		wd.addresses.Range(func(key, value any) bool { ips = append(ips, key.([4]byte)); return true })

		for _, ip := range ips {

			addr := fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], wd.probePort)

			switch TcpProbe(addr) {
			case false:
				wd.events <- Event{GatewayAddr: ip[:], Kind: GatewayFailed} // TODO: Add Throttling and deduplication
			case true:
				wd.events <- Event{GatewayAddr: ip[:], Kind: GatewayAvailable} // TODO: Add Throttling and deduplication
			}

		}

		time.Sleep(wd.probeInterval)

	}
}

func (wd *Watchdog) GetProbePort() int {
	return int(wd.probePort)
}

func (wd *Watchdog) GetWatchedAddrStatus(addr [4]byte) (valAvailable addressStatus, keyExists bool) {
	val, exists := wd.addresses.Load(addr)

	return val.(addressStatus), exists
}

func (wd *Watchdog) SetWatchedAddrStatusFailed(addr [4]byte) {
	wd.addresses.Store(addr, addressStatus{Available: false, LastColdStartTS: time.Unix(0, 0)}) //TODO: make it cleaner - keep previous time ?
}

func (wd *Watchdog) SetWatchedAddrStatusAvaialble(addr [4]byte) {
	var newLastColdStartTS time.Time
	addrStatVal, _ := wd.addresses.Load(addr) // TODO: make a check for ok
	prevAvailable, prevLastColdStartTS := addrStatVal.(addressStatus).Available, addrStatVal.(addressStatus).LastColdStartTS

	if !prevAvailable {
		newLastColdStartTS = time.Now()
		wd.addresses.Store(addr, addressStatus{Available: true, LastColdStartTS: newLastColdStartTS}) //TODO: make it cleaner - keep previous time ?
		return
	}
	//
	if prevLastColdStartTS.Add(20 * time.Second).Before(time.Now()) { //TODO: 2x HoldTime - should be add as config parameter (also used in  egw manager)
		wd.addresses.Store(addr, addressStatus{Available: true, LastColdStartTS: prevLastColdStartTS}) //TODO: make it cleaner - keep previous time ?
		return
	}

}

func (wd *Watchdog) GetWatchedAddrStatusLastColdStartTS(addr [4]byte) time.Time {
	addrStatus, _ := wd.addresses.Load(addr) // TODO: make a check for ok

	return addrStatus.(addressStatus).LastColdStartTS
}
