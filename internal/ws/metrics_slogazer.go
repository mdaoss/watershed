// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	bpfl "watershed/internal/bpfloader"
	"watershed/internal/config"
	"watershed/internal/server"
	"golang.org/x/time/rate"
)

type SloGazer struct {
	registry   *prometheus.Registry
	limiter    *rate.Limiter
	config     *config.Config
	bpfObjects *bpfl.BpfObjects
}

func NewSloGazer(
	lc cell.Lifecycle,
	config *config.Config,
	bpfObjects *bpfl.BpfObjects,
) *SloGazer {

	msrv := SloGazer{
		// New dedicated registry for ws metrics only
		registry:   prometheus.NewRegistry(),
		limiter:    rate.NewLimiter(rate.Every(30*time.Second), 1), // Once per 30 second
		config:     config,
		bpfObjects: bpfObjects,
	}

	lc.Append(cell.Hook{OnStop: msrv.Stop}) // delegate licfecycle handling to HIVE

	go msrv.Start()

	return &msrv
}

func (msrv *SloGazer) MetricsUpdate() {
	msrv.egressmapMetricsUpdate()
}

func (msrv *SloGazer) MetricsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if msrv.limiter.Allow() {
			msrv.MetricsUpdate()
		}
		next.ServeHTTP(w, req)
	})
}

func (msrv *SloGazer) Start() error {
	msrv.registry.MustRegister(ws_egressmap_max_entries_count)
	msrv.registry.MustRegister(ws_egressmap_curr_entries_count)

	go func() {

		metricsHttpServer, addPattern := server.NewHttpServer(context.TODO(),
			"0.0.0.0:"+strconv.Itoa(int(msrv.config.MetricsPort)),
			5, 5)

		handler := promhttp.HandlerFor(msrv.registry, promhttp.HandlerOpts{})
		addPattern("/metrics", msrv.MetricsHandler(handler))

		slog.Info(
			"Metrics exposed at  http://0.0.0.0:" + strconv.Itoa(int(msrv.config.MetricsPort)) + "/metrics")

		if err := metricsHttpServer.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				slog.Error("unable to listen metrics port", slog.Any("error", err))
			}
		}
	}()

	return nil //TODO: Add error handling
}

func (msrv *SloGazer) Stop(ctx cell.HookContext) error {

	//TODO:  not implemented lc Stop Hook

	return nil
}
