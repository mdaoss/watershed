// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package prober

import (
	"errors"
	"log/slog"
	"net"
	"time"

	"golang.org/x/time/rate"
)

type ProbeKind uint8

const (
	_ ProbeKind = iota
	Healtcheck
)

var failedProbesCount int
var limiter = rate.NewLimiter(rate.Every(5*time.Second), 1) // Once per 5 second

func TcpProbe(addr string) bool {
	time.Sleep(50 * time.Millisecond)                        // TODO: Backoff ?????
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second) // TODO:  replace magic number with const
	if err != nil {
		var noper *net.OpError
		if errors.As(err, &noper) {
			if limiter.Allow() {
				slog.Warn("tcpProbe failed", slog.Any("error", noper.Err.Error()), slog.Any("addr", noper.Addr.String()), slog.Any("failedProbesCount", failedProbesCount))
				failedProbesCount++
			} else {
				failedProbesCount++
			}
		}
		return false
	}

	//_, err = conn.Write([]byte{byte(Healtcheck)})
	//if err != nil {
	//	log.Printf("\n\n probe write failed due \n err: %+#v   \n\n", err)

	//}

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	failedProbesCount = 0 //TODO: use atomic?
	return true
}
