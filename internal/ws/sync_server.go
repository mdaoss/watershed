// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	bpfl "watershed/internal/bpfloader"
	"watershed/internal/ws/pb"
)

const (
	snatMapKeySize = 14
	snatMapValSize = 40
)

type Server struct {
	pb.UnimplementedSyncerServer

	syncManager        *Manager
	serverInstance     *grpc.Server
	egressIPListUint32 []uint32
	srcPodIPListUint32 []uint32
}

func (m *Manager) StartWSServer() {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", m.config.PeerPort)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		m.logger.Error("unable to start sync server listener", slog.Any("addr", listenAddr), slog.Any("error", err))
		return
	}

	m.server = Server{
		syncManager:    m,
		serverInstance: grpc.NewServer(),
	}

	pb.RegisterSyncerServer(m.server.serverInstance, &m.server)
	m.logger.Info("sync server started", slog.Any("addr", listenAddr))

	if err := m.server.serverInstance.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		m.logger.Error("sync server stopped with error", slog.Any("error", err))
	}
}

func (s *Server) HandleUpdate(_ context.Context, req *pb.MapUpdateReq) (*pb.MapUpdateResp, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}

	if req.MapType != uint32(bpfl.SNAT_V4_EXTERNAL) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported map type: %d", req.MapType)
	}

	snatMap, err := s.snatMapOrError()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	for _, event := range req.Events {
		if err := validateSNATEvent(event); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		if !s.shouldApplySNATEvent(event.Key, event.Value) {
			continue
		}

		if err := applyMapEvent(snatMap, event); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to apply update: %v", err)
		}
	}

	latency := int64(0)
	if req.SentAt > 0 {
		latency = time.Now().UnixNano() - req.SentAt
	}

	return &pb.MapUpdateResp{Ok: true, UpdateLatency: latency}, nil
}

func (s *Server) FullSync(_ context.Context, req *pb.FullSyncReq) (*pb.FullSyncResp, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}

	if req.MapType != uint32(bpfl.SNAT_V4_EXTERNAL) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported map type: %d", req.MapType)
	}

	snatMap, err := s.snatMapOrError()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	events, err := dumpSNATEvents(snatMap, s.shouldApplySNATEvent)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to dump snat map: %v", err)
	}

	return &pb.FullSyncResp{MapType: req.MapType, Events: events}, nil
}

func (s *Server) snatMapOrError() (*ebpf.Map, error) {
	if s == nil || s.syncManager == nil || s.syncManager.bpfObjects == nil || s.syncManager.bpfObjects.SnatExtV4 == nil {
		return nil, errors.New("snat map is not initialized")
	}

	return s.syncManager.bpfObjects.SnatExtV4, nil
}

func (s *Server) shouldApplySNATEvent(key, val []byte) bool {
	if len(s.egressIPListUint32) == 0 && len(s.srcPodIPListUint32) == 0 {
		return true
	}

	if len(key) != snatMapKeySize || len(val) != snatMapValSize {
		return false
	}

	if len(s.egressIPListUint32) > 0 {
		if matched, _ := IsSnatEntryRelatedToEgressIPListAsUInt32(key, val, s.egressIPListUint32); matched {
			return true
		}
	}

	if len(s.srcPodIPListUint32) > 0 {
		if matched, _ := IsSnatEntryRelatedToPodIPListAsRevAddrUInt32(key, val, s.srcPodIPListUint32); matched {
			return true
		}
	}

	return false
}

func validateSNATEvent(event *pb.MapUpdateEvent) error {
	if event == nil {
		return errors.New("received nil map update event")
	}

	if len(event.Key) != snatMapKeySize {
		return fmt.Errorf("invalid key size: got=%d want=%d", len(event.Key), snatMapKeySize)
	}

	if len(event.Value) != snatMapValSize {
		return fmt.Errorf("invalid value size: got=%d want=%d", len(event.Value), snatMapValSize)
	}

	switch event.Type {
	case uint32(MAP_UPDATE), uint32(MAP_DELETE):
		return nil
	default:
		return fmt.Errorf("unsupported event type: %d", event.Type)
	}
}

func applyMapEvent(dstMap *ebpf.Map, event *pb.MapUpdateEvent) error {
	switch event.Type {
	case uint32(MAP_UPDATE):
		return dstMap.Update(event.Key, event.Value, ebpf.UpdateAny)
	case uint32(MAP_DELETE):
		err := dstMap.Delete(event.Key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unsupported event type: %d", event.Type)
	}
}

func dumpSNATEvents(srcMap *ebpf.Map, allow func(key, val []byte) bool) ([]*pb.MapUpdateEvent, error) {
	iter := srcMap.Iterate()
	var key [snatMapKeySize]byte
	var val [snatMapValSize]byte
	updates := make([]*pb.MapUpdateEvent, 0, 1024)

	for iter.Next(&key, &val) {
		k := append([]byte(nil), key[:]...)
		v := append([]byte(nil), val[:]...)
		if allow != nil && !allow(k, v) {
			continue
		}

		updates = append(updates, &pb.MapUpdateEvent{
			Key:   k,
			Value: v,
			Type:  uint32(MAP_UPDATE),
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return updates, nil
}

func (m *Manager) watchUpdates(ctx context.Context, workersN int, rbReader *ringbuf.Reader, processor mapDataProcessor, out chan ValueRequest) {
	if rbReader == nil || processor == nil {
		m.logger.Error("unable to watch updates: reader or processor is nil")
		return
	}

	if workersN < 1 {
		workersN = 1
	}

	events := out
	ownsChannel := false
	if events == nil {
		ch := make(chan ValueRequest, workersN*128)
		events = ch
		ownsChannel = true
	}

	var wg sync.WaitGroup
	if ownsChannel {
		for workerID := 0; workerID < workersN; workerID++ {
			wg.Add(1)
			go func(id int, updates <-chan ValueRequest) {
				defer wg.Done()
				m.SendEvents(id, updates)
			}(workerID, events)
		}
	}

	defer func() {
		if ownsChannel {
			close(events)
			wg.Wait()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := processor.readRingBuf(rbReader); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			m.logger.Error("unable to read ringbuf update", slog.Any("error", err))
			continue
		}

		outEvent := processor.exportAsValueRequest()
		if outEvent == nil {
			processor.clear()
			continue
		}

		copied := ValueRequest{
			Key:       append([]byte(nil), outEvent.Key...),
			Value:     append([]byte(nil), outEvent.Value...),
			MapType:   outEvent.MapType,
			EventType: outEvent.EventType,
			Mapid:     outEvent.Mapid,
			SendAt:    outEvent.SendAt,
		}

		select {
		case <-ctx.Done():
			return
		case events <- copied:
		}

		processor.clear()
	}
}

func processUpdateEvents(dstMap *ebpf.Map, events []*pb.MapUpdateEvent, logger *slog.Logger) {
	if dstMap == nil {
		if logger != nil {
			logger.Error("unable to process update events: destination map is nil")
		}
		return
	}

	for _, event := range events {
		if err := validateSNATEvent(event); err != nil {
			if logger != nil {
				logger.Error("skipping malformed event", slog.Any("error", err))
			}
			continue
		}

		if err := applyMapEvent(dstMap, event); err != nil {
			if logger != nil {
				logger.Error("unable to apply update event", slog.Any("error", err), slog.Any("eventType", event.Type))
			}
		}
	}
}
