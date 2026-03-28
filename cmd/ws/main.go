// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	cv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"

	"github.com/cilium/cilium/pkg/k8s/utils"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"watershed/internal/bpfloader"
	"watershed/internal/idallocator"
	"watershed/internal/sysctl"

	"watershed/internal/config"
	egw "watershed/internal/egressgateway"
	egressmap "watershed/internal/egressmap"
	"watershed/internal/logs"
	"watershed/internal/prober"
	ws "watershed/internal/ws"
)

func main() {

	// Allows to add startup delay to be able to connect via debugger at the beginning
	if val := os.Getenv("WS_STARTUP_DELAY_SECONDS"); val != "" {
		d, err := strconv.Atoi(val)
		if err != nil {
			fmt.Println(err.Error())
		}

		time.Sleep(time.Duration(d) * time.Second)
	}

	runningConfig := config.InitRunningConfig()
	logger := logs.InitLogger(runningConfig)

	watershed := hive.New(
		endpointmanager.Cell,
		client.Cell,
		bpfloader.Cell,
		ws.Cell,
		egw.Cell,
		sysctl.Cell,
		node.LocalNodeStoreCell,

		cell.Provide(
			// Load already initialized config into Hive to reuse them in other Constructors
			func() *config.Config {
				return runningConfig
			},
			func() sysctl.Config {
				return sysctl.Config{
					ProcFs: "/host/proc", // TODO: define  procfs via config
				}
			},

			// Reusing Already pre-created Policy Map from Cilium Datapath
			LoadExistingEgressMap,

			// Initialize with required configuration
			LoadDaemonConfig, // TODO: Remove

			// Provide  Custom  CRD - based IdentityAllocator
			LoadCRDIdentityAllocator,

			// Provide required resources
			NewCiliumNodeResource,
			k8s.CiliumSlimEndpointResource,
			prober.NewWatchdog,
			ws.NewSloGazer, // should be moved to dedicated module
		),

		cell.Invoke(func(*ws.Manager) {}),
		cell.Invoke(func(*egw.Manager) {}),
		cell.Invoke(func(*ws.SloGazer) {}),
	)

	//watershed.RegisterFlags(pflag.CommandLine)
	//pflag.Parse()

	// Same pointer to slog.Logger  will be provided to  all constructors above
	watershed.Run(logger)
}

func NewCiliumEndpointResource(lc cell.Lifecycle, c client.Clientset) resource.Resource[*types.CiliumEndpoint] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped[*cv2.CiliumEndpointList](c.CiliumV2().CiliumEndpoints(""))
	return resource.New[*types.CiliumEndpoint](lc, lw)
}

func NewCiliumNodeResource(lc cell.Lifecycle, c client.Clientset) resource.Resource[*cv2.CiliumNode] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped[*cv2.CiliumNodeList](c.CiliumV2().CiliumNodes())
	return resource.New[*cv2.CiliumNode](lc, lw)
}

// TODO:: ADD retry  of egress map load in a loop ?
func LoadExistingEgressMap() egressmap.PolicyMap {
	pm, err := egressmap.OpenPinnedPolicyMap()
	if err != nil {
		panic(fmt.Errorf("unable to load policyMap pre-created by cilium: %v", err))
	}

	return pm
}

func LoadDaemonConfig() *option.DaemonConfig {
	// Compatability CiliumDaemon config, to enable usage of cilium libraries
	return &option.DaemonConfig{
		EnableIPv4:                   true,
		EnableIPv6:                   false,
		KVStore:                      "",
		IdentityAllocationMode:       option.IdentityAllocationModeCRD,
		AutoCreateCiliumNodeResource: false,
		DisableCiliumEndpointCRD:     false,
		PolicyMapEntries:             16348, //TODO: Not Effective Value  - managed by cilium config
		EnableIPv4EgressGateway:      true,
		Debug:                        false,        // TODO: var for debug
		ProcFs:                       "/host/proc", // TODO: var for hostproc
	}
}

// TODO: Try to replace  CRD via cilium client API
// https://github.com/cilium/cilium/blob/v1.17.2/pkg/client/endpoint.go#L15
func LoadCRDIdentityAllocator(c client.Clientset) cache.IdentityAllocator {
	//TODO: handle done signal integrate via HIVE
	stopCh := make(chan struct{})
	alloc, _ := idallocator.NewCRDIdentityAllocator(&c, stopCh)

	return alloc
}
