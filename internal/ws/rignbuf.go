// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"github.com/cilium/ebpf/ringbuf"
	bpfl "watershed/internal/bpfloader"
)

type RBufReaderMap map[bpfl.BpfMapName]*ringbuf.Reader
type RingbufCloser func()

func MustInitRingBuffReaders(bpfObjects *bpfl.BpfObjects) (RBufReaderMap, RingbufCloser) {
	rbReaderSnatPart0, err := ringbuf.NewReader(bpfObjects.MapEventsSnatextPart0)
	if err != nil {
		panic(err)
	}

	readers := map[bpfl.BpfMapName]*ringbuf.Reader{
		bpfl.Cilium_snat_v4_external_map_name + "part_0": rbReaderSnatPart0,
	}

	f := func() {
		for _, r := range readers {
			r.Close()
		}
	}

	return readers, f

}
