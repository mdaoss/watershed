// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"log/slog"
)

func (m *Manager) InitGoBGPServer() {
	m.gobgp.Serve()
	m.logger.Info("started gobgp grpc server")

	if err := m.gobgp.StartWithPreCheck(
		context.TODO(),
		m.config.BGPConfig.ASN,
		m.config.BGPConfig.NeighborList,
	); err != nil {
		m.logger.Error("unable to start bgp sessions", slog.Any("error", err))
	}

}
