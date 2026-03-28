// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"encoding/binary"
	"log/slog"
	"net"
	"slices"
	unsafe "unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

const (
	SNAT_KEY_EGRESS_IP_OFFSET_START = 0
	SNAT_KEY_EGRESS_IP_OFFSET_END   = 4
	SNAT_VAL_EGRESS_IP_OFFSET_START = 32
	SNAT_VAL_EGRESS_IP_OFFSET_END   = 36

	SNAT_VAL_POD_REV_ADDR_OFFSET_START = 32
	SNAT_VAL_POD_REV_ADDR_OFFSET_END   = 36

	CT4_KEY_POD_DADDR_OFFSET_START = 0
	CT4_KEY_POD_DADDR_OFFSET_END   = 4
)

const BPF_NAME_LEN = 16

// Order matters!
type MapUpdateEventType uint32

const (
	MAP_UPDATE MapUpdateEventType = iota
	MAP_DELETE
)

type mapDataProcessor interface {
	readRingBuf(*ringbuf.Reader) error
	exportAsValueRequest() *ValueRequest
	//	// Checks Is processed entry related to node syncer manager
	//	isRelatedToManager(m *Manager) bool
	clear()
}

func IsSnatEntryRelatedToEgressIPListAsUInt32(key []byte, val []byte, eipList []uint32) (matched bool, eip uint32) {

	eip = binary.BigEndian.Uint32(key[SNAT_KEY_EGRESS_IP_OFFSET_START:SNAT_KEY_EGRESS_IP_OFFSET_END])
	if slices.Contains(eipList, eip) {
		return true, eip
	}

	eip = binary.BigEndian.Uint32(val[SNAT_VAL_EGRESS_IP_OFFSET_START:SNAT_VAL_EGRESS_IP_OFFSET_END])
	if slices.Contains(eipList, eip) {
		return true, eip
	}

	return false, 0
}

func IsSnatEntryRelatedToPodIPListAsRevAddrUInt32(key []byte, val []byte, podIPList []uint32) (matched bool, revAddr uint32) {

	revAddr = binary.BigEndian.Uint32(val[SNAT_VAL_POD_REV_ADDR_OFFSET_START:SNAT_VAL_POD_REV_ADDR_OFFSET_END])
	if slices.Contains(podIPList, revAddr) {
		return true, revAddr
	}
	return false, 0
}

func IsCT4EntryRelatedToPodIPListAsDaddrUInt32(key []byte, val []byte, podIPList []uint32) (matched bool, revAddr uint32) {

	revAddr = binary.BigEndian.Uint32(key[CT4_KEY_POD_DADDR_OFFSET_START:CT4_KEY_POD_DADDR_OFFSET_END])
	if slices.Contains(podIPList, revAddr) {
		return true, revAddr
	}
	return false, 0
}

func logSnatEvent(l *slog.Logger, msg string, key *IPv4CtTuple, val IPv4NatEntry, attrs ...slog.Attr) {
	l.Info(
		msg,
		slog.Any("mapKind", "snat_v4_ext"),
		slog.Any("daddr", key.DAddr),
		slog.Any("saddr", key.SAddr),
		slog.Any("dport", portNtoaLE(key.DPort)),
		slog.Any("sport", portNtoaLE(key.SPort)),
		slog.Any("to_saddr", val.ToAddress),
		slog.Any("to_sport", portNtoaLE(val.ToPort)),
		attrs,
	)
}

func reverseSnatEntry(key []byte, val []byte) ([]byte, []byte) {
	//,"mapKind":"snat_v4_ext","daddr":[10,26,82,186],"saddr":[10,53,117,213],"dport":60838,"sport":80,"to_saddr":[29,64,0,15],"to_sport":60838}
	//"mapKind":"snat_v4_ext","daddr":[10,53,117,213],"saddr":[29,64,0,15],"dport":80,"sport":60838,"to_saddr":[10,26,82,186],"to_sport":60838}

	keyParsed := bytesToSnatKey(key)
	valParsed := bytesToSnatVal(val)

	revKey := keyParsed
	revVal := valParsed

	revKey.DAddr = keyParsed.SAddr
	revKey.SAddr = valParsed.ToAddress
	revKey.DPort = keyParsed.SPort
	revKey.SPort = keyParsed.DPort
	revVal.ToAddress = keyParsed.DAddr
	revVal.ToPort = valParsed.ToPort

	return snatKeyToBytes(revKey), snatValToBytes(revVal)

}

func bytesToSnatKey(buf []byte) IPv4CtTuple {
	var keyOut = IPv4CtTuple{}
	//TODO: use special compiler directives  to make it more safe????
	keyOut = *(*IPv4CtTuple)(unsafe.Pointer(&buf[0])) // Copy value IN time, as unsafe pointer may be cleaned via GC
	return keyOut
}

func snatKeyToBytes(key IPv4CtTuple) []byte {

	//TODO: use special compiler directives  to make it more safe????
	keyOut := (*(*[14]byte)(unsafe.Pointer(&key)))[:] // Copy value IN time, as unsafe pointer may be cleaned via GC
	return keyOut
}

func bytesToSnatVal(buf []byte) IPv4NatEntry {
	var valOut = IPv4NatEntry{}
	//TODO: use special compiler directives  to make it more safe????
	valOut = *(*IPv4NatEntry)(unsafe.Pointer(&buf[0])) // Copy value IN time, as unsafe pointer may be cleaned via GC

	return valOut
}

func snatValToBytes(key IPv4NatEntry) []byte {

	//TODO: use special compiler directives  to make it more safe????
	keyOut := (*(*[40]byte)(unsafe.Pointer(&key)))[:] // Copy value IN time, as unsafe pointer may be cleaned via GC
	return keyOut
}

func inetNtoaLE(b [4]byte) string {
	return net.IP(b[:]).String()
}

func portNtoaLE(b uint16) uint16 {
	// Convert to little-endian
	// To swap bytes, we shift the lower byte to the higher position
	// and the higher byte to the lower position.
	littleEndianUint16 := (b&0xFF)<<8 | (b>>8)&0xFF
	return littleEndianUint16
}
