// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"watershed/internal/bgp"
	bpfl "watershed/internal/bpfloader"
	"watershed/internal/config"
	"watershed/internal/debug"
	"watershed/internal/link"
	"watershed/internal/ws/pb"
)

var runUpdatePeerConfigOnce sync.Once

type Manager struct {
	//m            sync.Mutex // TODO: Make manager related concurrency safer
	rBufMap                 RBufReaderMap
	rBufCloser              RingbufCloser
	bpfObjects              *bpfl.BpfObjects
	listenAddress           net.IP
	peerAddress             net.IP
	config                  *config.Config
	isActive                atomic.Bool
	IsPeerAbsentBefore      atomic.Bool
	isLeader                atomic.Bool
	isLeaderBefore          atomic.Bool //TODO: Refactor and Join al leader election stuff to one struct
	isInitialPeerUpdateDone atomic.Bool
	client                  pb.SyncerClient
	server                  Server
	egressIPList            []net.IP
	egressIPListUint32      []uint32 // Alternative representation of IP address for quick comparison
	srcPodIPListUint32      []uint32 // Alternative representation of IP address for quick comparison
	logger                  *slog.Logger
	SNATFullSyncDone        bool //TODO: Make it better and cleaner
	CT4FullSyncDone         bool //TODO: Make it better and cleaner
	gobgp                   bgp.GoBGP
}

func NewSyncManager(lc cell.Lifecycle, cfg *config.Config, logger *slog.Logger, bpfo *bpfl.BpfObjects) *Manager {

	var m Manager
	m.config = cfg
	m.logger = logger

	caller := debug.CallerName(0)
	m.logger.Debug("called NewSyncManager constructor", slog.Any("caller", caller))

	// In newer kernels (5.11 and later), this is less critical as eBPF memory accounting moved to memory cgroups
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// ORDER MATTERS!!!
	// Has built-in closer method in struct
	m.bpfObjects = bpfo

	m.initWatershedStateMap()

	m.rBufMap, m.rBufCloser = MustInitRingBuffReaders(m.bpfObjects)

	// Initialization of BGP Server for peering with Remote
	ip, err := link.GetLocalSrcIP()
	if err != nil {
		m.logger.Error("unable to detect bgp routerId", slog.Any("error", err))

	}

	bgpTimersOption := bgp.WithTimers(
		m.config.BGPConfig.HoldTime,
		m.config.BGPConfig.KeepaliveInterval,
		m.config.BGPConfig.ConnectRetry,
	)
	m.gobgp = *bgp.New(m.logger, ip.String(), bgp.WithGRPC(true), bgpTimersOption)

	m.InitGoBGPServer()

	//runUpdatePeerConfigOnce.Do(func() {
	go m.UpdatePeerConfig()
	//	})

	lc.Append(cell.Hook{OnStart: m.Start, OnStop: m.Stop}) // delegate licfecycle handling to HIVE

	return &m
}

func StartSync(m *Manager) {
	// If it is a passive watershed instance  -  bpf map sync isn't required
	go m.StartWSServer() // Server is always on, for bootstrapping on cold start via peer updates
	//go m.StartWSClient()

}

func (m *Manager) initWatershedStateMap() (err error) { //TODO: Refactor
	// store info about current process to prevent updates caused by watershed itself
	// filtering by HostPid is done on ebpf side
	var key uint32 = 0
	var pid = uint32(os.Getpid())
	wsState := bpfl.WatershedState{
		HostPid: pid, //! hostPID:true is required in POD template
	}

	err = m.bpfObjects.WsState.Update(&key, &wsState, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update the map: %v", err)
	}

	m.logger.Info("app state initialized", slog.Any("PID", pid))

	return nil
}

// IsLeader
// TODO: Refactor implicit value update Logic
func (m *Manager) IsLeader() bool {
	if m.listenAddress == nil {
		newLeadershipState := false
		m.isLeaderBefore.Store(m.isLeader.Load())
		m.isLeader.Store(newLeadershipState)

		return m.isLeader.Load()
	}

	if m.peerAddress == nil {
		newLeadershipState := true
		m.isLeaderBefore.Store(m.isLeader.Load())
		m.isLeader.Store(newLeadershipState)

		return m.isLeader.Load()
	}

	localVal := binary.BigEndian.Uint32(m.listenAddress[:])
	peerVal := binary.BigEndian.Uint32(m.peerAddress[:])

	newLeadershipState := (localVal > peerVal)

	// isLeaderBefore helps to detects leadership change to reduce reduntand operations on leadership check
	m.isLeaderBefore.Store(m.isLeader.Load())
	m.isLeader.Store(newLeadershipState)

	return m.isLeader.Load()
}

func (m *Manager) IsLeadershipChanged() bool {
	return m.isLeaderBefore != m.isLeader
}

func (m *Manager) Start(ctx cell.HookContext) error { return nil } // just stub now

func (m *Manager) Stop(ctx cell.HookContext) error {

	//Shadowing ctx to adjust deadline
	ctx, cancel := context.WithTimeout(ctx, m.config.TerminationGracePeriod*time.Second)
	defer cancel() // Always call cancel to release resources

	m.logger.Warn("manager for debug", slog.Any("manager", *m))

	m.logger.Warn(
		"started grace shutdown",
		slog.Any("gracePeriod", m.config.TerminationGracePeriod),
	)

	//Sync All nat rules before stoppng bgp
	m.snatFullSync(ctx)

	// Stopping announcing  BGP route
	// As route propagation takes a delay, stop bgp first
	err := m.gobgp.Stop(ctx) // TODO: Healthcheck  for prober
	if err != nil {
		m.logger.Error("error on gobgp shutdown", slog.Any("error", err))
	}

	// Stopping server immediatelly, to  send new traffc via new node
	if m.server.serverInstance != nil {
		m.server.serverInstance.Stop()
	}
	m.logger.Warn(
		"all prerequisites for grace shutdown was done; exiting ....",
		slog.Any("gracePeriod", m.config.TerminationGracePeriod),
	)

	//TODO: Test this logic for gracefullness
	return err
}
