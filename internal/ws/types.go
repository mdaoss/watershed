// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

type ValueResponse struct {
	Key           []byte
	Value         []byte
	MapType       uint32
	EventType     uint32
	Mapid         uint32
	UpdateLatency int64
}

type ValueRequest struct {
	Key       []byte
	Value     []byte
	MapType   uint32
	EventType uint32
	Mapid     uint32
	SendAt    int64
}

type ipv4_ct_tuple struct {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	daddr uint32
	saddr uint32
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	dport   uint16
	sport   uint16
	nexthdr uint8
	flags   uint8
}

type nat_entry struct {
	created  uint64
	needs_ct uint64 /* Only single bit used. */
	pad1     uint64 /* Future use. */
	pad2     uint64 /* Future use. */
}

type lb4_reverse_nat struct {
	address uint16
	port    uint16
}

type ipv4_nat_entry struct {
	common   nat_entry
	nat_info lb4_reverse_nat
}
