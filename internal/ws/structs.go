// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"encoding/binary"
	"net"
)

// IPv4CtTuple corresponds to struct ipv4_ct_tuple
type IPv4CtTuple struct {
	DAddr   [4]byte // __be32 daddr (big-endian 32-bit)
	SAddr   [4]byte // __be32 saddr (big-endian 32-bit)
	DPort   uint16  // __be16 dport (big-endian 16-bit)
	SPort   uint16  // __be16 sport (big-endian 16-bit)
	Nexthdr uint8   // __u8 nexthdr
	Flags   uint8   // __u8 flags
	// No padding needed as it's packed in C
}

// Lb4ReverseNat corresponds to struct lb4_reverse_nat
type Lb4ReverseNat struct {
	Address [4]byte // __be32 address (big-endian 32-bit)
	Port    uint16  // __be16 port (big-endian 16-bit)
}

// IPv4NatEntry corresponds to struct ipv4_nat_entry
type IPv4NatEntry struct {
	Created   uint64  // __u64 created
	NeedsCt   uint64  // __u64 needs_ct (only single bit used)
	Pad1      uint64  // __u64 pad1 (future use)
	Pad2      uint64  // __u64 pad2 (future use)
	ToAddress [4]byte // __be32 to_saddr
	ToPort    uint16  // __be16 to_sport
	Pad3      uint16  /// just to fix err
}

// Helper methods to access the union fields in different ways

// GetNatInfo returns the data as Lb4ReverseNat
func (e *IPv4NatEntry) GetNatInfo() Lb4ReverseNat {
	return Lb4ReverseNat{
		Address: e.ToAddress, // Using ToSAddr for address
		Port:    e.ToPort,    // Using ToSPort for port
	}
}

// SetNatInfo sets the data from Lb4ReverseNat
func (e *IPv4NatEntry) SetNatInfo(natInfo Lb4ReverseNat) {
	e.ToAddress = natInfo.Address
	e.ToPort = natInfo.Port
}

// GetToS returns the to_saddr and to_sport fields
func (e *IPv4NatEntry) GetToS() ([4]byte, uint16) {
	return e.ToAddress, e.ToPort
}

// SetToS sets the to_saddr and to_sport fields
func (e *IPv4NatEntry) SetToS(addr [4]byte, port uint16) {
	e.ToAddress = addr
	e.ToPort = port
}

// GetToD returns the to_daddr and to_dport fields
func (e *IPv4NatEntry) GetToD() ([4]byte, uint16) {
	return e.ToAddress, e.ToPort
}

// SetToD sets the to_daddr and to_dport fields
func (e *IPv4NatEntry) SetToD(addr [4]byte, port uint16) {
	e.ToAddress = addr
	e.ToPort = port
}

// Additional helper functions for network byte order conversion

// IPv4ToUint32 converts net.IP to big-endian uint32 representation
func IPv4ToUint32(ip net.IP) uint32 {
	if len(ip) == 16 { // IPv4-mapped IPv6 address
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip.To4())
}

// Uint32ToIPv4 converts big-endian uint32 to net.IP
func Uint32ToIPv4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

//Byte Arrays for IP Addresses: Used [4]byte instead of uint32 to maintain the exact byte representation and make it easier to work with Go's net.IP type.
//
//Union Handling: Go doesn't have unions, so I created a struct that contains all possible union fields and provided helper methods to access them in different ways (similar to how the C union would be used).
//
//Big-Endian Fields: The original C structures use __be32 and __be16 which are big-endian (network byte order). The helper functions IPv4ToUint32 and Uint32ToIPv4 help with conversion between Go's types and network byte order.
//
//Packed Attribute: The C __attribute__((packed)) is handled naturally in Go since Go structs don't have padding between fields (they're already packed).
//
//Port Fields: Used uint16 for port fields since they represent port numbers.
//
//The helper methods allow you to use the IPv4NatEntry in different ways, similar to how the C union would be used with different field names accessing the same memory
