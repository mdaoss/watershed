// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bgp

import "time"

type BGPConfig struct {
	ASN               uint32           `yaml:"asn"`
	RouterID          string           `yaml:"routerID"`
	HoldTime          time.Duration    `yaml:"holdTime"`
	KeepaliveInterval time.Duration    `yaml:"keepaliveInterval"`
	ConnectRetry      time.Duration    `yaml:"connectRetry"`
	NeighborList      []NeighborConfig `yaml:"neighborList"`
}

type NeighborConfig struct {
	Description string `yaml:"description"`
	IP          string `yaml:"ip"`
	ASN         uint32 `yaml:"asn"`
	Password    string `yaml:"password"`
}
