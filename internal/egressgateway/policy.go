// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"go4.org/netipx"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"watershed/internal/prober"
)

const MaxGatewayCount = 2

// policyGatewayConfig is the internal representation of an egress gateway,
// describing which node should act as egress gateway for a given policy.
type policyGatewayConfig struct {
	nodeSelector api.EndpointSelector
	iface        string
	egressIP     netip.Addr
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string
	// egressIP is the IP used to SNAT traffic
	egressIP netip.Addr
	// gatewayIP is the node internal IP of the gateway
	gatewayIPList [MaxGatewayCount]netip.Addr
	// localNodeConfiguredAsGateway tells if the local node is configured to
	// act as an egress gateway node for this config.
	// This information is used to decide if it is necessary to relax the rp_filter
	// on the interface used to SNAT traffic
	localNodeConfiguredAsGateway bool
}

// PolicyConfig is the internal representation of CiliumEgressGatewayPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix

	policyGwConfig *policyGatewayConfig

	matchedEndpoints map[endpointID]*endpointMetadata
	gatewayConfig    gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *PolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) {
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)

	for _, endpoint := range epDataStore {
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

func (config *policyGatewayConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

// WS - Redefined Gateway selection to support  multiple gateways
func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	// WS -- replace magic number 128 to  const MaximumNodesCount
	availableGateways := make([]netip.Addr, 0, 3)
	gwc := gatewayConfig{
		egressIP:      netip.IPv4Unspecified(),
		gatewayIPList: [MaxGatewayCount]netip.Addr{GatewayNotFoundIPv4},
	}

	policyGwc := config.policyGwConfig

	for _, node := range manager.nodes {
		if policyGwc.selectsNodeAsGateway(node) { // WS -- STATE SYNC HERE
			addr, ok := netipx.FromStdIP(node.GetK8sNodeIP())
			if !ok {
				continue
			}

			if !prober.TcpProbe(addr.String() + ":" + strconv.Itoa(manager.prober.GetProbePort())) {
				continue
			}
			manager.prober.AddIPv4ToWatchList(addr.As4())

			availableGateways = append(availableGateways, addr)
			if len(availableGateways) >= MaxGatewayCount {
				break
			}
		}
	}

	avGwLen := len(availableGateways)
	for avGwLen < MaxGatewayCount {
		availableGateways = append(availableGateways, GatewayNotFoundIPv4)
		avGwLen = len(availableGateways)
	}

	gwc.gatewayIPList = [MaxGatewayCount]netip.Addr{} // Watershed - Manage array size via MaxGatewayCount
	for i := 0; i < MaxGatewayCount; i++ {
		gwc.gatewayIPList[i] = availableGateways[i]
	}

	//WS -- Each node as local now
	err := gwc.deriveFromPolicyGatewayConfig(policyGwc)
	if err != nil {
		logger := log.WithFields(logrus.Fields{
			logfields.CiliumEgressGatewayPolicyName: config.id,
			logfields.Interface:                     policyGwc.iface,
			logfields.EgressIP:                      policyGwc.egressIP,
		})
		logger.WithError(err).Error("Failed to derive policy gateway configuration")
	}

	config.gatewayConfig = gwc

}

// deriveFromPolicyGatewayConfig retrieves all the missing gateway configuration
// data (such as egress IP or interface) given a policy egress gateway config
// runs only for nodes selected as gateway
func (gwc *gatewayConfig) deriveFromPolicyGatewayConfig(gc *policyGatewayConfig) error {

	gwc.localNodeConfiguredAsGateway = false

	switch {
	case gc.egressIP.IsValid():
		// If the gateway config specifies an egress IP, use the interface with that IP as egress
		// interface

		// interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIP = gc.egressIP

	default:
		gwc.egressIP = EgressIPNotFoundIPv4
		return fmt.Errorf("defined Invalid egress ip  in CEGP: %v", gc.egressIP)

	}

	gwc.localNodeConfiguredAsGateway = true

	return nil
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(netip.Addr, netip.Prefix, bool, *gatewayConfig)) {

	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			isExcludedCIDR := false
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, isExcludedCIDR, &config.gatewayConfig)
			}

			isExcludedCIDR = true
			for _, excludedCIDR := range config.excludedCIDRs {
				f(endpointIP, excludedCIDR, isExcludedCIDR, &config.gatewayConfig)
			}
		}
	}
}

// ParseCEGP takes a CiliumEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseCEGP(cegp *v2.CiliumEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var excludedCIDRs []netip.Prefix

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	destinationCIDRs := cegp.Spec.DestinationCIDRs
	if destinationCIDRs == nil {
		return nil, fmt.Errorf("destinationCIDRs can't be empty")
	}

	egressGateway := cegp.Spec.EgressGateway
	if egressGateway == nil {
		return nil, fmt.Errorf("egressGateway can't be empty")
	}

	if egressGateway.Interface != "" && egressGateway.EgressIP != "" {
		return nil, fmt.Errorf("gateway configuration can't specify both an interface and an egress IP")
	}

	policyGwc := &policyGatewayConfig{
		nodeSelector: api.NewESFromK8sLabelSelector("", egressGateway.NodeSelector),
		iface:        egressGateway.Interface,
	}
	// EgressIP is not a required field, validate and parse it only if non-empty
	if egressGateway.EgressIP != "" {
		addr, err := netip.ParseAddr(egressGateway.EgressIP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse egress IP %s: %w", egressGateway.EgressIP, err)
		}
		policyGwc.egressIP = addr
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %w", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range cegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse excluded CIDR %s: %w", cidr, err)
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, egressRule := range cegp.Spec.Selectors {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", prefixedNsSelector, egressRule.PodSelector))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
		} else {
			return nil, fmt.Errorf("cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		excludedCIDRs:     excludedCIDRs,
		matchedEndpoints:  make(map[endpointID]*endpointMetadata),
		policyGwConfig:    policyGwc,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCEGPConfigID takes a CiliumEgressGatewayPolicy CR and returns only the config id
func ParseCEGPConfigID(cegp *v2.CiliumEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: cegp.Name,
	}
}
