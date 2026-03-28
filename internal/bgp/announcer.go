// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bgp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// GoBGP - клиент для взаимодействия по протоколу BGP.
type GoBGP struct {
	leaderPolicy  *api.Policy
	slavePolicy   *api.Policy
	routerID      string
	srv           *server.BgpServer
	logger        *gobgpLogger
	holdTime      time.Duration
	keepaliveTime time.Duration
	conRetryTime  time.Duration
	grpcAddress   string
}

// Option - опции инициализации клиента.
type Option func(*GoBGP)

// New - создает нового клиента.
func New(logger *slog.Logger, routerID string, opts ...Option) *GoBGP {

	cl := &GoBGP{routerID: routerID, logger: &gobgpLogger{}}

	for _, opt := range opts {
		opt(cl)
	}

	gobgpLogger := gobgpLogger{
		slog:  logger,
		debug: false,
	}
	cl.logger = &gobgpLogger
	cl.logger.SetLevel(log.LogLevel(slog.LevelError)) //TODO: make BGP Log level configurable

	cl.srv = server.NewBgpServer(
		server.GrpcListenAddress(cl.grpcAddress),
		server.LoggerOption(cl.logger),
	)

	return cl
}

// WithTimers - задает значения holdTime и keepaliveInterval для пиров.
func WithTimers(hold, keepalive, retry time.Duration) Option {
	return func(c *GoBGP) {
		c.holdTime = hold
		c.keepaliveTime = keepalive
		c.conRetryTime = retry
	}
}

// WithGRPC - использовать gobgp grpc server.
func WithGRPC(ok bool) Option {
	return func(c *GoBGP) {
		if ok {
			c.grpcAddress = grpcAddress
		}
	}
}

// GetBgp - возвращает gobgp server.
func (gbgp *GoBGP) GetBgp() *server.BgpServer {
	return gbgp.srv
}

// Serve - запуск BGP  сервера.
func (gbgp *GoBGP) Serve() {
	go gbgp.srv.Serve()
}

// Start - запуск BGP сессии.
func (gbgp *GoBGP) Start(ctx context.Context, asn uint32) error {
	if err := gbgp.srv.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   gbgp.routerID,
			ListenPort: -1, // Listen Port of BGP Server  (-1) - disabled//TODO: activate via debug flag?
			//ListenAddresses:  []string{"0.0.0.0"},
			UseMultiplePaths: true,
		},
	}); err != nil {
		return fmt.Errorf("start bgp: %w", err)
	}

	return nil
}

// Stop - остановка BGP сессии.
func (gbgp *GoBGP) Stop(ctx context.Context) error {
	if err := gbgp.srv.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
		return fmt.Errorf("stopped bgp: %w", err)
	}

	return nil
}

// AddPeer - добавление пира.
func (gbgp *GoBGP) AddPeer(ctx context.Context, asn uint32, neighbor, password string) error {
	if err := gbgp.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: neighbor,
			PeerAsn:         asn,
			AuthPassword:    password,
		},
		EbgpMultihop: &api.EbgpMultihop{Enabled: true},
		Timers: &api.Timers{Config: &api.TimersConfig{
			HoldTime:          uint64(gbgp.holdTime.Seconds()),
			KeepaliveInterval: uint64(gbgp.keepaliveTime.Seconds()),
			ConnectRetry:      uint64(gbgp.conRetryTime.Seconds()),
		}},
	}}); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	return nil
}

// AddHostRoute - добавление маршрута до хоста.
func (gbgp *GoBGP) AddHostRoute(ctx context.Context, ip string, nexthop string) error {
	prefix, _ := apb.New(&api.IPAddressPrefix{Prefix: ip, PrefixLen: 32})
	nh, _ := apb.New(&api.NextHopAttribute{NextHop: nexthop})
	org, _ := apb.New(&api.OriginAttribute{Origin: 0})

	if _, err := gbgp.srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		Nlri:   prefix,
		Pattrs: []*apb.Any{org, nh},
	}}); err != nil {
		return fmt.Errorf("add path: %w", err)
	}

	return nil
}

// WatchPeers - отслеживание событий изменения состояния пиров.
func (gbgp *GoBGP) WatchPeers(ctx context.Context) error {
	if err := gbgp.srv.WatchEvent(ctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
	}, func(r *api.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE {
			gbgp.logger.Info("peer state change", log.Fields{
				"addr":  p.Peer.State.NeighborAddress,
				"state": p.Peer.State.SessionState,
			})
		}
	}); err != nil {
		return fmt.Errorf("watch peers: %w", err)
	}

	return nil
}

// IsBGPServerRunning - checks is gobgpServer response with info about running bgp server
// If err, then gobgp server  is down
func (gbgp *GoBGP) IsBGPServerRunning(ctx context.Context) bool {
	resp, err := gbgp.srv.GetBgp(context.TODO(), &api.GetBgpRequest{})
	if err != nil {
		return false
	}

	return !(resp.Global.Asn == 0) // Api replies with ASN 0 even without started bgp
}

func (gbgp *GoBGP) StartWithPreCheck(ctx context.Context, asn uint32, neighborList []NeighborConfig) error {
	if !gbgp.IsBGPServerRunning(ctx) {
		err := gbgp.Start(ctx, asn)
		if err != nil {
			return err
		}

		err = gbgp.CreateLeaderPrependPolicy(globalPrependLeaderPolicyName, asn, leaderAsnRepeatN)
		if err != nil {
			gbgp.logger.Error(fmt.Sprintf("failed to add leader global prepend policy: %v", err), log.Fields{})
		}
		err = gbgp.CreateFollowerPrependPolicy(globalPrependSlavePolicyName, asn, followerAsnRepeatN)
		if err != nil {
			gbgp.logger.Error(fmt.Sprintf("failed to add slave global prepend policy: %v", err), log.Fields{})
		}

		gbgp.logger.Info("created global prepend policies", log.Fields{})

		for _, neighbor := range neighborList {
			if err := gbgp.AddPeer(context.TODO(), neighbor.ASN, neighbor.IP, neighbor.Password); err != nil {
				gbgp.logger.Error(
					"unable to add peer", log.Fields{
						"peerIP":  neighbor.IP,
						"peerASN": neighbor.ASN,
						"error":   err,
					},
				)
			}
		}
	}
	return nil
}

func (gbgp *GoBGP) StopWithCheck(ctx context.Context) error {
	if gbgp.IsBGPServerRunning(ctx) {
		return gbgp.Stop(ctx)
	}
	return nil
}

// SoftResetPeer
// Policies are applied on export
// Removing policy does not affect already advertised routes
// ResetPeer is required to propagate changes to Peers
func (gbgp *GoBGP) SoftResetPeer(peerAddress string) (err error) {

	err = gbgp.srv.ResetPeer(context.TODO(), &api.ResetPeerRequest{
		Address:   peerAddress, // all - reserved value. means ALL peers
		Soft:      true,        // Just re-advertise routes
		Direction: api.ResetPeerRequest_BOTH,
	})

	return err
}

func (gbgp *GoBGP) WithdrawEgressRoute(ctx context.Context, prefix net.IP) (err error) {

	//netPrefix, err := netip.ParsePrefix(prefix)
	//if err != nil {
	//panic(err)
	//}

	//nlri := bgp.NewIPAddrPrefix(uint8(netPrefix.Bits()), netPrefix.Addr().String())
	ones, _ := prefix.DefaultMask().Size()
	nlri := bgp.NewIPAddrPrefix(uint8(ones), prefix.String())

	nlriAny, err := apiutil.MarshalNLRI(nlri)
	if err != nil {
		panic(err)
	}

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	path := &api.Path{
		Nlri:       nlriAny,
		Family:     family,
		IsWithdraw: true,
	}

	req := &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    family,
		Path:      path,
	}

	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := gbgp.srv.DeletePath(rctx, req); err != nil {

	}

	return err
}

//// EnsurePrepend will add/replace only if different
//func (gbgp *GoBGP) EnsurePrepend(asn uint32, repeatn uint32) {
//	// --- Step 1: Check if policy already exists ---
//	existing, err := gbgp.api.ListPolicy(context.TODO(), &api.ListPolicyRequest{Name: policyName})
//	if err == nil {
//		for {
//			p, err := existing.Recv()
//			if err != nil {
//				break
//			}
//			if len(p.Policy.Statements) > 0 {
//				acts := p.Policy.Statements[0].Actions
//				if acts != nil && acts.BgpActions != nil && acts.BgpActions.AsPrepend != nil {
//					ap := acts.BgpActions.AsPrepend
//					if ap.Asn == asn && ap.Repeatn == repeatn {
//						fmt.Printf("ℹ️ Prepend already set (ASN %d x%d), nothing to do\n", asn, repeatn)
//						return
//					}
//				}
//			}
//		}
//	}
//
//	// --- Step 2: Clean up old version if any ---
//
//	// --- Step 3: Create new policy ---
//}
//
//// RemovePrepend safely removes policy + assignment (idempotent)
//func (gbgp *GoBGP) RemovePrepend() {
//
//	_ = gbgp.api.DeletePolicyAssignment(context.TODO(), &api.DeletePolicyAssignmentRequest{
//		Assignment: &api.PolicyAssignment{
//			Name:      "global",
//			Direction: api.PolicyDirection_EXPORT,
//		},
//	})
//	fmt.Println("Global prepend removed (if it existed)")
//}
//
