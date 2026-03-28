// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bgp

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/osrg/gobgp/v3/pkg/log"
)

type gobgpLogger struct {
	slog  *slog.Logger
	debug bool
}

func (l *gobgpLogger) Panic(msg string, fields log.Fields) {
	l.slog.Error(msg, fieldSlice(fields)...)
	os.Exit(1)
}

func (l *gobgpLogger) Fatal(msg string, fields log.Fields) {
	l.slog.Error(msg, fieldSlice(fields)...)
	os.Exit(1)
}

func (l *gobgpLogger) Error(msg string, fields log.Fields) {
	l.slog.Error(msg, fieldSlice(fields)...)
}

func (l *gobgpLogger) Warn(msg string, fields log.Fields) {
	l.slog.Warn(msg, fieldSlice(fields)...)
}

func (l *gobgpLogger) Info(msg string, fields log.Fields) {
	if l.debug {
		l.slog.Info(msg, fieldSlice(fields)...)
	}
}

func (l *gobgpLogger) Debug(msg string, fields log.Fields) {

	if l.debug {
		l.slog.Debug(msg, fieldSlice(fields)...)
	}
}

func (l *gobgpLogger) SetLevel(lvl log.LogLevel) {
	slog.SetLogLoggerLevel(slog.Level(lvl))
}

func (l *gobgpLogger) GetLevel() log.LogLevel {
	return log.LogLevel(log.DebugLevel)
}

func fieldSlice(fields log.Fields) []any {
	fSlice := []any{}
	for k, v := range fields {
		if _, ok := v.(fmt.Stringer); ok {
			fSlice = append(fSlice, k, fmt.Sprintf("%v", v))

			continue
		}

		fSlice = append(fSlice, k, v)
	}

	return fSlice
}
