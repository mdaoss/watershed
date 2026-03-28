// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	bpfl "watershed/internal/bpfloader"
	"watershed/internal/ws/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func (m *Manager) SendEvents(id int, events <-chan ValueRequest) {
	err := pinGoroutineToCpu(id)
	if err != nil {
		m.logger.Error("failed to assign sender to cpu", slog.Any("senderID", id), slog.Any("cpuID", id))
		return
	}
	m.logger.Info("sender is assigned to cpu", slog.Any("senderID", id), slog.Any("cpuID", id))

	niceValue := -19
	err = makeThreadTheNicest(niceValue)
	if err != nil {
		m.logger.Error("failed to assign nice value for sender", slog.Any("senderID", id))
		return
	}
	m.logger.Info("sender is assigned to cpu", slog.Any("workerID", id), slog.Any("niceValue", niceValue))

	for e := range events {
		m.sendEventUpdate(e)
	}
}

func (m *Manager) sendEventUpdate(msg ValueRequest) {

	// Prevent errors due to of  uninitialized peer  -- if peer radress is present - map was loaded //TODO: make it better
	for m.peerAddress == nil {
		time.Sleep(50 * time.Millisecond)
	}

	target := fmt.Sprintf("%v:%v", m.peerAddress.String(), m.config.PeerPort)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	//	grpc.WithDefaultServiceConfig(serviceConfig),
	)
	if err != nil {
		m.logger.Error(
			"unable to create conn to process batch update to peer",
			slog.Any("error", err),
		)
		return
	}

	client := pb.NewSyncerClient(conn)
	keyParsed := bytesToSnatKey(msg.Key)
	valParsed := bytesToSnatVal(msg.Value)
	logSnatEvent(m.logger, "loaded local event from ringbuf", &keyParsed, valParsed)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*1500)

	// run the RPC
	// TODO: CONNECTION RE_ESTABLISHING
	_, err = client.HandleUpdate(ctx, &pb.MapUpdateReq{
		MapType: msg.MapType,
		Events: []*pb.MapUpdateEvent{{
			Key:   msg.Key,
			Value: msg.Value,
			Type:  msg.EventType,
		},
		},
		SentAt: msg.SendAt,
	})
	if err != nil {
		m.logger.Error("unable to send local update to peer", slog.Any("error", err))
		if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) { // Connection reset by peer || broken pipe
			m.client = nil //TODO: use mutex
		}
		cancel()
	}

	if msg.MapType == uint32(bpfl.SNAT_V4_EXTERNAL) {
		logSnatEvent(m.logger, "local update successfully processed on remote peer", &keyParsed, valParsed)
	}
	cancel()
}
