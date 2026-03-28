// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"errors"
	"time"
	unsafe "unsafe"

	"github.com/cilium/ebpf/ringbuf"
	bpfl "watershed/internal/bpfloader"
)

var ErrSampleSizeDoesNotMatch = errors.New("size of received ringbuf record doesn't match size of struct")

const sizeOfStructMapDataSnatExt = 54 // Key (14 bytes) + Value( 40 bytes)
// MapDataSnatExt - size 54 bytes
type MapDataSnatExt struct {
	Key   [14]byte
	Value [40]byte
}

func (md *MapDataSnatExt) readRingBuf(rbReader *ringbuf.Reader) error {
	record, err := rbReader.Read() // Is concurrency safe ?
	//log.Printf("Read from ringbuffer: %v ;; %v", record, err)
	if err != nil {
		return err
	}

	// должна быть строгая проверка, что длина record.RawSample точно равна размеру целевой структуры.
	if len(record.RawSample) == sizeOfStructMapDataSnatExt {
		//TODO: use special compiler directives  to make it more safe????
		// Copy value IN time, as unsafe pointer may be cleaned via GC
		*md = *(*MapDataSnatExt)(unsafe.Pointer((*[sizeOfStructMapDataSnatExt]byte)(record.RawSample)))
		return nil
	}

	return err
}

func (md *MapDataSnatExt) exportAsValueRequest() *ValueRequest {
	return &ValueRequest{
		Key:       md.Key[:],
		Value:     md.Value[:],
		MapType:   uint32(bpfl.SNAT_V4_EXTERNAL),
		EventType: uint32(MAP_UPDATE),
		Mapid:     uint32(bpfl.SNAT_V4_EXTERNAL),
		SendAt:    time.Now().UnixNano(),
	}
}

func (md *MapDataSnatExt) clear() { md = &MapDataSnatExt{} }
