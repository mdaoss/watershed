// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"time"

	bpfl "watershed/internal/bpfloader"
	"watershed/internal/ws/pb"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Start Sync CLient - start sending local updates to Peer
// TODO: Need to support peer change
func (m *Manager) StartWSClient() {
	slog.Info("watershed instance is operating in ACTIVE mode.")

	// continiously dialing to peer if it is nil
	go m.dialPeer()
	go m.snatFullSync(context.TODO())

	go m.watchUpdates(context.TODO(), runtime.NumCPU()-1, m.rBufMap[bpfl.Cilium_snat_v4_external_map_name+"part_0"], &MapDataSnatExt{}, nil)
}

// dialPeer - coniniously support  net client in active state
func (m *Manager) dialPeer() {
	// Prevent crash of  uninitialized peerAddress
	for m.peerAddress == nil {
		time.Sleep(100 * time.Millisecond)
	}

	for {
		// Prevent crash on start if server is unavailable
		if m.client == nil {
			target := fmt.Sprintf("%v:%v", m.peerAddress.String(), m.config.PeerPort)

			conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
			//, grpc.WithContextDialer(withTimeoutDial))
			if err != nil { // TODO: HANDLE ERR CONREFUSED  + BACKOFF
				m.logger.Error(fmt.Sprintf("error has occured on client net dial: %v", err))

				time.Sleep(100 * time.Millisecond) // TODO: Backoff ?????
				continue
			}

			m.client = pb.NewSyncerClient(conn)

		}
		time.Sleep(100 * time.Millisecond) // TODO: Backoff ?????
	}
}

func withTimeoutDial(ctx context.Context, target string) (net.Conn, error) {
	var timeout time.Duration = 3 * time.Second //TODO: Remove magic number

	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	return net.DialTimeout("tcp", target, timeout)
}

// snatFullSync - push local snat entries to remote Peer
func (m *Manager) snatFullSync(ctx context.Context) {

	return //TODO: NO-OP early exit for nosync scenario - must be refactored

	// Prevent crash of  uninitialized ebpfMaps  -- if pee radress is present - map was loaded //TODO: make it better
	//for m.peerAddress == nil {
	//	time.Sleep(100 * time.Millisecond)
	//}

	req := &pb.FullSyncReq{
		MapType: uint32(bpfl.SNAT_V4_EXTERNAL), //TODO: make it more clear
		SentAt:  time.Now().Unix(),
	}

	var failedSyncCount int
	var limiter = rate.NewLimiter(rate.Every(3*time.Second), 1) // Once per 3 second
	// Prevent crash of  uninitialized peerAddress
	for !m.SNATFullSyncDone {

		if m.client != nil {
			resp, err := m.client.FullSync(ctx, req)
			if err != nil {
				failedSyncCount++
				if limiter.Allow() {
					m.logger.Error(
						"unable to make snat fullsync:",
						slog.Any("failedSyncCount", failedSyncCount),
						slog.Any("error", err),
					)
				}
				time.Sleep(100 * time.Millisecond) // TODO: Backoff ?????
				continue

			}

			processUpdateEvents(m.bpfObjects.SnatExtV4, resp.Events, m.logger)
			m.SNATFullSyncDone = true
			m.logger.Info(fmt.Sprintf("fulsync with peer  %v is completed", m.peerAddress))
		}
		time.Sleep(100 * time.Millisecond) // TODO: Backoff ?????
	}
}

//
