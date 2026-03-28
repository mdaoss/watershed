// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	egressmap "watershed/internal/egressmap"
	"watershed/internal/peermap"
	"watershed/internal/prober"
	"watershed/internal/sysctl"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.IPv4Unspecified()
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
	// EgressIPNotFoundIPv4 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv4 = netip.IPv4Unspecified()
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgateway",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
	cell.Provide(newPolicyResource),
)

type eventType int

const (
	eventNone = eventType(1 << iota)
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateEndpoint
	eventDeleteEndpoint
)

type Config struct {
	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	EgressGatewayReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-reconciliation-trigger-interval", def.EgressGatewayReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// nodes stores nodes sorted by their name. The entries are sorted
	// to ensure consistent gateway selection across all agents.
	nodes []nodeTypes.Node

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// prober checks availability  of used egress gateways
	prober *prober.Watchdog

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap communicates the active policies to the datapath.
	policyMap egressmap.PolicyMap

	// peerMap writes peer address per node address to bpf map.
	// Used by waterhed sync subsystem
	peerMap peermap.PeerMap

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconcipkg/egressgatewayliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired egress gateway state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	sysctl sysctl.Sysctl

	// NAT and conntrack sync manager
	//syncManager *syncer.Manager
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmap.PolicyMap
	Policies          resource.Resource[*Policy]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Sysctl            sysctl.Sysctl

	Lifecycle cell.Lifecycle
}

func NewEgressGatewayManager(p Params, prober *prober.Watchdog) (out struct {
	cell.Out
	*Manager
}, err error) {

	out.Manager, err = newEgressGatewayManager(p, prober)
	if err != nil {
		return out, err
	}

	return out, nil
}

func newEgressGatewayManager(p Params, prober *prober.Watchdog) (*Manager, error) {
	manager := &Manager{
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP:       make(map[string][]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		policyMap:                     p.PolicyMap,
		policies:                      p.Policies,
		ciliumNodes:                   p.Nodes,
		endpoints:                     p.Endpoints,
		sysctl:                        p.Sysctl,
		prober:                        prober,
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_reconciliation",
		MinInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

			manager.Lock()
			defer manager.Unlock()

			manager.reconcileLocked()
		},
	})
	if err != nil {
		return nil, err
	}

	manager.reconciliationTrigger = t

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.processEvents(ctx)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			wg.Wait()
			return nil
		},
	})

	return manager, nil
}

func (manager *Manager) setEventBitmap(events ...eventType) {
	for _, e := range events {
		manager.eventsBitmap |= e
	}
}

func (manager *Manager) eventBitmapIsSet(events ...eventType) bool {
	for _, e := range events {
		if manager.eventsBitmap&e != 0 {
			return true
		}
	}

	return false
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context) {
	var policySync, nodeSync, endpointSync bool // TODO: ProbeSync ??

	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync || !endpointSync {
			return
		}

		manager.Lock()
		defer manager.Unlock()

		if manager.allCachesSynced {
			return
		}

		manager.allCachesSynced = true
		manager.setEventBitmap(eventK8sSyncDone)
		manager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)

	policyEvents := manager.policies.Events(ctx)
	nodeEvents := manager.ciliumNodes.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))
	probeEvents := manager.prober.Events() // TODO:  Add ctx and rate limiter

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleNodeEvent(event)
			}

		case event := <-endpointEvents:
			if event.Kind == resource.Sync {
				endpointSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleEndpointEvent(event)
			}
		case event := <-probeEvents:
			manager.handleProbeEvent(event)
			//event.Done(nil) ?????
		}

	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := manager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

func (manager *Manager) handleProbeEvent(event prober.Event) {
	manager.Lock()
	defer manager.Unlock()

	switch event.Kind {
	case prober.GatewayFailed:
		//manager.prober.RemoveIPv4FromWatchList([4]byte(event.GatewayAddr)) // TODO: More clean types
		manager.prober.SetWatchedAddrStatusFailed([4]byte(event.GatewayAddr))
		manager.reconciliationTrigger.TriggerWithReason("prober detected gateway failure")
	case prober.GatewayAvailable:
		manager.prober.SetWatchedAddrStatusAvaialble([4]byte(event.GatewayAddr))
		//TODO:  Dirty hack to handle  route propagation  via cold start; make it better
		previousStatus, ok := manager.prober.GetWatchedAddrStatus([4]byte(event.GatewayAddr))
		if !ok {
			panic("non-existent gateway adress in probe event")
		}
		if !previousStatus.Available {
			time.Sleep(time.Now().Sub(previousStatus.LastColdStartTS)) // Must be at least 2xHoldTime //TODO: make it configurabl
		}
		//manager.prober.RemoveIPv4FromWatchList([4]byte(event.GatewayAddr)) // TODO: More clean types
		//TODO: deduplication due to  coldStartWait
		manager.reconciliationTrigger.TriggerWithReason("prober detected gateway is available")
	case prober.BGPFailure:
		//TODO: NotImplemented
	}
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, policy.Name)

	config, err := ParseCEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse CiliumEgressGatewayPolicy")
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumEgressGatewayPolicy")
	} else {
		logger.Debug("Updated CiliumEgressGatewayPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

	manager.policyConfigs[config.id] = config

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseCEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressGatewayPolicy: policy not found")
	}

	logger.Debug("Deleted CiliumEgressGatewayPolicy")

	delete(manager.policyConfigs, configID)

	manager.setEventBitmap(eventDeletePolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy deleted")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	if endpoint.Identity == nil {
		logger.Warning("Endpoint is missing identity metadata, skipping update to egress policy.")
		return nil
	}

	securityIdentity := noOverflowConvEndpointIDoSecurityID(endpoint.Identity.ID)
	if identityLabels, err = manager.getIdentityLabels(securityIdentity); err != nil {
		logger.WithError(err).
			Warning("Failed to get identity labels for endpoint")
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug("Updated CiliumEndpoint")
	} else {
		logger.Debug("Added CiliumEndpoint")
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, endpoint.UID)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object

	if event.Kind == resource.Upsert {
		event.Done(manager.addEndpoint(endpoint))
	} else {
		manager.deleteEndpoint(endpoint)
		event.Done(nil)
	}
}

// handleNodeEvent takes care of node upserts and removals.
func (manager *Manager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	manager.Lock()
	defer manager.Unlock()

	// Find the node if we already have it.
	nidx, found := slices.BinarySearchFunc(manager.nodes, node, func(a nodeTypes.Node, b nodeTypes.Node) int {
		return cmp.Compare(a.Name, b.Name)
	})

	if event.Kind == resource.Delete {
		// Delete the node if we're aware of it.
		if found {
			manager.nodes = slices.Delete(manager.nodes, nidx, nidx+1)
		}

		manager.reconciliationTrigger.TriggerWithReason("node deleted")
		return
	}

	// Update the node if we have it, otherwise insert in the correct
	// position.
	if found {
		manager.nodes[nidx] = node
	} else {
		manager.nodes = slices.Insert(manager.nodes, nidx, node)
	}

	manager.reconciliationTrigger.TriggerWithReason("node updated")
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore)
	}
}

func (manager *Manager) updatePoliciesBySourceIP() {
	manager.policyConfigsBySourceIP = make(map[string][]*PolicyConfig)

	for _, policy := range manager.policyConfigs {
		for _, ep := range policy.matchedEndpoints {
			for _, epIP := range ep.ips {
				ip := epIP.String()
				manager.policyConfigsBySourceIP[ip] = append(manager.policyConfigsBySourceIP[ip], policy)
			}
		}
	}
}

// policyMatches returns true if there exists at least one policy matching the
// given parameters.
//
// This method takes:
//   - a source IP: this is an optimization that allows to iterate only through
//     policies that reference an endpoint with the given source IP
//   - a callback function f: this function is invoked for each policy and for
//     each combination of the policy's endpoints and destination/excludedCIDRs.
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - a boolean value indicating if the CIDR belongs to the excluded ones
// - the gatewayConfig of the  policy
//
// This method returns true whenever the f callback matches one of the endpoint
// and CIDR tuples (i.e. whenever one callback invocation returns true)
func (manager *Manager) policyMatches(sourceIP netip.Addr, f func(netip.Addr, netip.Prefix, bool, *gatewayConfig) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		for _, ep := range policy.matchedEndpoints {
			for _, endpointIP := range ep.ips {
				if endpointIP != sourceIP {
					continue
				}

				isExcludedCIDR := false
				for _, dstCIDR := range policy.dstCIDRs {
					if f(endpointIP, dstCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}

				isExcludedCIDR = true
				for _, excludedCIDR := range policy.excludedCIDRs {
					if f(endpointIP, excludedCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) relaxRPFilter() error {
	var sysSettings []tables.Sysctl
	ifSet := make(map[string]struct{})

	for _, pc := range manager.policyConfigs {

		// WS - Relax IP filter Always as multiple gateways is possible now
		if !pc.gatewayConfig.localNodeConfiguredAsGateway {
			continue
		}

		ifaceName := pc.gatewayConfig.ifaceName
		if _, ok := ifSet[ifaceName]; !ok {
			ifSet[ifaceName] = struct{}{}
			sysSettings = append(sysSettings, tables.Sysctl{
				Name:      []string{"net", "ipv4", "conf", ifaceName, "rp_filter"},
				Val:       "2",
				IgnoreErr: false,
			})
		}
	}

	if len(sysSettings) == 0 {
		return nil
	}

	return manager.sysctl.ApplySettings(sysSettings)
}

func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR)
		policyVal, policyPresent := egressPolicies[policyKey]

		gatewayIPList := gwc.gatewayIPList
		if excludedCIDR {
			gatewayIPList = [MaxGatewayCount]netip.Addr{ExcludedCIDRIPv4}
		}

		if policyPresent && policyVal.Match(gwc.egressIP, gwc.gatewayIPList) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP,
			logfields.GatewayIP:       gatewayIPList,
		})

		if err := manager.policyMap.Update(endpointIP, dstCIDR, gwc.egressIP, gatewayIPList); err != nil {
			logger.WithError(err).Error("Error applying egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) bool {
			gatewayIPList := gwc.gatewayIPList
			if excludedCIDR {
				gatewayIPList = [MaxGatewayCount]netip.Addr{ExcludedCIDRIPv4}
			}

			a := policyKey.Match(endpointIP, dstCIDR)
			b := policyVal.Match(gwc.egressIP, gatewayIPList)
			return a && b
		}

		if manager.policyMatches(policyKey.GetSourceIP(), matchPolicy) {
			continue
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressAddr(),
			logfields.GatewayIP:       policyVal.GetGatewayAddrList(),
		})

		if err := manager.policyMap.Delete(policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy removed")
		}
	}
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileLocked() {
	if !manager.allCachesSynced {
		return
	}

	switch {
	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	case manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint, eventK8sSyncDone):
		manager.updatePoliciesMatchedEndpointIDs()
		fallthrough
	case manager.eventBitmapIsSet(eventAddPolicy, eventDeletePolicy):
		manager.updatePoliciesBySourceIP()
	}

	manager.regenerateGatewayConfigs()

	// Sysctl updates are handled by a reconciler, with the initial update attempting to wait some time
	// for a synchronous reconciliation. Thus these updates are already resilient so in case of failure
	// our best course of action is to log the error and continue with the reconciliation.
	//
	// The rp_filter setting is only important for traffic originating from endpoints on the same host (i.e.
	// egw traffic being forwarded from a local Pod endpoint to the gateway on the same node).
	// Therefore, for the sake of resiliency, it is acceptable for EGW to continue reconciling gatewayConfigs
	// even if the rp_filter setting are failing.
	if err := manager.relaxRPFilter(); err != nil {
		log.WithError(err).Error("Error relaxing rp_filter for gateway interfaces. "+
			"Selected egress gateway interfaces require rp_filter settings to use loose mode (rp_filter=2) for gateway forwarding to work correctly. ",
			"This may cause connectivity issues for egress gateway traffic being forwarded through this node for Pods running on the same host. ")
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()

	// clear the events bitmap
	manager.eventsBitmap = 0

	manager.reconciliationEventsCount.Add(1)
}
