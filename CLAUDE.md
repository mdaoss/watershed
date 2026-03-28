# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Watershed is a Cilium Egress Gateway synchronization system.
It extends Cilium's eBPF datapath to support 2 egress gateways and disables the egress gateway control plane from the Cilium daemon.
This egress gateway implementation has its own control plane based on Cilium's egress gateway control plane and interacts with Cilium BPF maps.
It monitors SNAT and conntrack BPF maps via eBPF probes, synchronizes NAT state between egress gateway nodes over gRPC, and advertises egress IPs via BGP. Deployed as a Kubernetes DaemonSet on egress gateway nodes.

## Build Commands

```bash
# Compile eBPF bytecode (requires clang)
clang -g -O2 -target bpf -I ./bpf -I ./bpf/include -c ./bpf/ws/ws.c -o ./internal/bpfloader/bpfloader_x86_bpfel.o

# Build Go binary
CGO_ENABLED=0 go build -o ws ./cmd/ws/

# Generate protobuf/gRPC stubs
go generate ./...

# Run tests
go test ./...

# Run a single test
go test ./internal/egressmap/ -run TestCell

# Docker builds
docker build -f deploy/docker/prod .   # production
docker build -f deploy/docker/dev .    # debug (includes Delve on :40000)
```

## Architecture

**Entry point:** `cmd/ws/main.go` — uses the Cilium Hive dependency injection framework to compose cells. Supports `WS_STARTUP_DELAY_SECONDS` env var for debugger attachment.

**Go module:** `watershed` (Go 1.25)

**Hive cells (registered in main.go):**
- `bpfloader.Cell` — loads compiled eBPF objects, attaches fentry probe on `htab_lru_map_update`
- `ws.Cell` — core sync manager: reads ringbuffer events, runs gRPC sync client/server, manages BGP advertisements
- `egw.Cell` (egressgateway) — watches CiliumEgressGatewayPolicy CRDs, configures gateway/egress IPs
- `sysctl.Cell` — tunes kernel parameters via `/host/proc/sys/net` (bind-mounted from host `/proc/sys/net`)

**Additionally registered in main.go:**
- `endpointmanager.Cell`, `client.Cell`, `node.LocalNodeStoreCell` (Cilium cells)
- `LoadExistingEgressMap()` — loads Cilium's pinned policy map
- `LoadDaemonConfig()` — compatibility config for Cilium libraries
- `LoadCRDIdentityAllocator()` — read-only identity allocator backed by CiliumIdentity CRDs
- `NewCiliumNodeResource()` — K8s resource watcher for CiliumNode objects

**Datapath (BPF):**
- `bpf/ws/ws.c` — fentry probe that intercepts updates to Cilium's `cilium_snat_v4_ext` LRU hash map
- Filters events by checking against `cilium_egress_gateway_policy` (LPM trie) and `egress_ip_set`
- Matching SNAT updates are pushed to userspace via a partitioned ringbuffer (`map_events_snatext_part_0`)
- BPF uses host PID tracking (`WatershedState` array map) to avoid re-proxying its own updates
- Header libraries in `bpf/ws/lib/`: `types.h`, `maps.h`, `filter.h`, `common.h`, `defs.h`, `stat.h`

**Sync layer (`internal/ws/`):**
- Leader/follower model: leader determined by IP address comparison (network byte order)
- Leader receives SNAT events from BPF and syncs to followers via gRPC
- gRPC server always runs (for bootstrapping); client only runs in active/leader mode
- `HandleUpdate` RPC for incremental updates, `FullSync` RPC for full state reconciliation
- Worker threads use CPU pinning and elevated nice values for performance
- Proto definitions in `proto/ws.proto`, generated stubs in `internal/ws/pb/`
- Prometheus metrics and SLO monitoring in `metrics_*.go` files

**BGP (`internal/bgp/`):**
- Uses GoBGP to advertise egress IPs as /32 host routes
- Leader prepends ASN twice, follower once — enables asymmetric routing preference
- Configured via `bgp` section in `ws.config.yaml`

**Egress maps (`internal/egressmap/`):**
- Reads Cilium's pre-existing pinned BPF maps (not created by this project)
- `PolicyMap` wraps the egress gateway policy LPM trie

**Egress gateway (`internal/egressgateway/`):**
- Watches CiliumEgressGatewayPolicy CRDs, reconciles endpoint state
- Updates BPF policy map, manages gateway/egress IP configuration
- Integrates with peermap for peer discovery (`ws_peers.go`)

**Prober (`internal/prober/`):**
- Gateway health watchdog: TCP probes to gateway addresses at configured interval
- Emits `GatewayAvailable`/`GatewayFailed` events

**Peer map (`internal/peermap/`):**
- Wraps BPF map at `/sys/fs/bpf/tc/globals/ws_peer_map`
- Used for peer discovery between egress gateway nodes

## All Internal Packages

| Package | Purpose |
|---------|---------|
| `bgp` | GoBGP integration for advertising egress IPs via BGP |
| `bpfloader` | Loads eBPF bytecode, attaches fentry probe, loads external Cilium maps |
| `config` | Reads `ws.config.yaml`, defines Config struct (no defaults — panics if missing) |
| `debug` | `CallerName()` utility for extracting function names from call stack |
| `defaults` | Constants (`DeadlineTimeout = 30s`) |
| `egressgateway` | Watches CiliumEgressGatewayPolicy CRDs, manages gateway/egress IPs |
| `egressmap` | Wraps Cilium's pinned BPF maps (policy LPM trie) |
| `idallocator` | Read-only identity allocator backed by CiliumIdentity CRDs |
| `link` | Network utilities: `GetLocalSrcIP()` via default route using netlink |
| `logs` | Initializes slog logger with JSON handler, Hive cell |
| `peermap` | Wraps `ws_peer_map` BPF map for peer discovery |
| `prober` | TCP health probes to gateway addresses, emits availability events |
| `server` | Generic HTTP server factory with graceful shutdown |
| `sysctl` | Tunes kernel parameters via host-mounted `/proc/sys/net` |
| `ws` | Core sync manager: ringbuffer events, gRPC sync, BGP, metrics |

## File Explanations
- `/bpf/extra/cilium.1.16.9.ha.egress.git.patch` — Patch over Cilium 1.16.9 with custom HA egress gateway implementation
- `/bpf/extra/cilium.1.16.9.ha.egress.active-passive.egress_gateway_ha.h.override` — Override patch for active-passive mode
- `/doc/cilium_egress_gateway_fixed.drawio.png` — Architecture diagram
- `/generate.go` — Code generation directives (protoc, bpf2go)

## Git Conventions

- **Commit style:** Use [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`)

## Key Conventions

- **Byte order:** BPF map keys/values use network byte order (big-endian) extensively — watch for `binary.BigEndian` usage
- **Config file:** Runtime config loaded from `ws.config.yaml` (mounted via ConfigMap), schema in `internal/config/config.go`. No defaults — config file is required and missing fields are zero-valued
- **Testing:** Uses `github.com/cilium/hive/hivetest` for cell-level tests; some tests are privileged (require BPF capabilities)
- **Logging:** Uses `log/slog` with JSON handler; log level configured in `ws.config.yaml`
- **Metrics:** Prometheus metrics via `github.com/prometheus/client_golang`, exposed on configured `metricsPort`

## Key Dependencies

- `github.com/cilium/cilium` v1.16.9 — Cilium libraries, hive framework, policy types
- `github.com/cilium/ebpf` v0.16.0 — eBPF map/program loading
- `github.com/cilium/hive` — Hive dependency injection framework
- `github.com/osrg/gobgp/v3` v3.37.0 — BGP protocol
- `google.golang.org/grpc` v1.71.0 — inter-node sync
- `google.golang.org/protobuf` v1.36.5 — protobuf serialization
- `github.com/prometheus/client_golang` v1.20.5 — Prometheus metrics
- `github.com/vishvananda/netlink` v1.3.1 — netlink for network interface management
- `k8s.io/client-go` v0.30.2 — Kubernetes client

## Deployment

Helm chart in `deploy/helm/`. Deploys as a DaemonSet with hostNetwork, hostPID, and privileged capabilities (CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON, CAP_SYS_NICE, CAP_IPC_LOCK, CAP_FOWNER, CAP_DAC_OVERRIDE). Mounts host `/sys/fs/bpf` for BPF map access and `/proc/sys/net` as `/host/proc/sys/net` for sysctl tuning. Config delivered via ConfigMap at `/ws.config.yaml`.
