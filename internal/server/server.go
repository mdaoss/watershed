// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// NewHttpServer - Provides configurable http server with context support
func NewHttpServer(ctx context.Context, addr string, readTimeout, writeTimeout int) (*http.Server, func(pattern string, handler http.Handler)) {
	mux := http.NewServeMux()

	addPattern := func(pattern string, handler http.Handler) {
		mux.Handle(pattern, handler)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
	}
	go func() {
		<-ctx.Done()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("unable to gracefully shutdown metrics server", slog.Any("error", err))
		}
	}()

	return server, addPattern
}
