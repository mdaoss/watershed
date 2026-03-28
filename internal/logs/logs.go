// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package logs

import (
	"log/slog"
	"os"

	"watershed/internal/config"
)

// TODO: // make singleton ??
func InitLogger(c *config.Config) *slog.Logger {
	var logger *slog.Logger

	lvl := new(slog.LevelVar)
	lvl.Set(slog.Level(c.LogLevel))

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     lvl,
		AddSource: false,
	}))

	slog.SetDefault(logger)

	return logger

}
