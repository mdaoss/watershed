// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bpfloader

import (
	"errors"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
	"golang.org/x/time/rate"
)

type traceProgCloser func()

type BpfObjects struct {
	bpfloaderObjects

	SnatExtV4       *ebpf.Map
	EgressGwV4      *ebpf.Map
	traceLinkCloser traceProgCloser
}

func InitBpfObjects(lc cell.Lifecycle) *BpfObjects {

	// Load pre-compiled programs and maps into the kernel.
	wsObjs := bpfloaderObjects{} //TODO: Pre pub cleanup
	mapOpts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: BpfPinPath,
		},
	}
	if err := loadBpfloaderObjects(&wsObjs, &mapOpts); err != nil {
		slog.Error("unable to load bpf objects. Exiting ...", slog.Any("error", err))
		os.Exit(1)
	}

	traceLinkCloser := mustAttachTracing(&wsObjs)

	bpfo := &BpfObjects{
		bpfloaderObjects: wsObjs,
		traceLinkCloser:  traceLinkCloser,
	}

	bpfo.mustLoadExternalMaps()

	lc.Append(cell.Hook{OnStop: bpfo.Stop}) // delegate licfecycle handling to HIVE

	return bpfo
}

func mustAttachTracing(wsObjs *bpfloaderObjects) (progCloser func()) {
	var err error

	fUpdateLRU, err := link.AttachTracing(link.TracingOptions{
		Program: wsObjs.bpfloaderPrograms.BpfProgKernHtabLruUpdate,
	})
	if err != nil {
		log.Fatalf("opening htab_lru_map_update_elem kprobe: %s", err)
	}

	progLinks := []link.Link{fUpdateLRU}

	f := func() {
		for _, l := range progLinks {
			l.Close()
		}
	}

	return f
}

func (bpfo *BpfObjects) Stop(ctx cell.HookContext) (err error) {
	err = bpfo.EgressGwV4.Close()
	if err != nil {
		return err
	}

	err = bpfo.SnatExtV4.Close()
	if err != nil {
		return err
	}

	bpfo.traceLinkCloser()

	return err
}

func (bpfo *BpfObjects) mustLoadExternalMaps() {
	//TODO: Node must be not ready untill all ebpf maps will be loaded
	bpfo.EgressGwV4 = loadExistingMap(cilium_egress_gw_policy_v4_pin_path)
	bpfo.SnatExtV4 = loadExistingMap(cilium_snat_v4_external_pin_path)
}

func loadExistingMap(pinPath string) *ebpf.Map {
	// Load the pinned map
	var mapHandle *ebpf.Map
	var err error
	var loadRetryCount int
	var limiter = rate.NewLimiter(rate.Every(5*time.Second), 1) // Once per 5 second

	for mapHandle == nil {
		mapHandle, err = ebpf.LoadPinnedMap(pinPath, nil)
		if errors.Is(err, os.ErrNotExist) {
			if limiter.Allow() {
				loadRetryCount++
				slog.Error("failed to load pinned map; isn't loaded by cilium yet?",
					slog.Any("pinPath", pinPath),
					slog.Any("error", err),
					slog.Any("loadRetryCount", loadRetryCount),
				)
			} else {
				loadRetryCount++
			}
			time.Sleep(100 * time.Millisecond) //TODO: remove timeout magic number
			continue

		}
		if err != nil {
			slog.Error("failed to load pinned map '%s': %v", pinPath, err)
			os.Exit(1)
		}
	}

	return mapHandle
}
