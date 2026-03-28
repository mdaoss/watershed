// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package generate

// git clone https://github.com/libbpf/libbpf.git bpf/include/libbpf/
//go:degenerate bpf2go -no-strip  -go-package syncer -output-dir "./internal/syncer/" -cflags "-I ./bpf -I ./bpf/include" -target amd64 -type EgressGWManagerState bpfel bpf/syncer/sync.c
//bpf2go -no-strip  -go-package syncer -output-dir "./internal/syncer/" -cflags "-I ./bpf -I ./bpf/include" -target amd64 -type EgressGWManagerState  sync   bpf/syncer/sync.c

//go:degenerate clang   -target bpf -O2 -g -I ./bpf -I ./bpf/include -D __TARGET_ARCH_X86  -D NOT_BPF2GO -c bpf/syncer/sync.c -o ./internal/syncer/sync_x86_bpfel_generated.o

//go:generate protoc --proto_path=./proto --go-grpc_out=./ ./proto/syncer.proto

//go:generate protoc --proto_path=./proto --go_out=./ ./proto/syncer.proto

//go:generate go build -o ws  ./cmd/
