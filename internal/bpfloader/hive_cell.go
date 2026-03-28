// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bpfloader

import (
	"github.com/cilium/hive/cell"
)

// Module() creates a named collection of cells.
var Cell = cell.Module(
	"bpfloader",                     // Module identifier (for e.g. logging and tracing)
	"Loads and provides bpfObjects", // Module title (for documentation)

	// Config registers a configuration when provided with the defaults
	// and an implementation of Flags() for registering the configuration flags.
	//cell.Config(config.DefaultConfig),

	// Provide the application the constructor for the server.
	cell.Provide(InitBpfObjects),
)
