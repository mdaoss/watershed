// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package bgp

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/log"
)

// EnablePrepend applies a global export policy that prepends ASN N times
func (gbgp *GoBGP) CreateLeaderPrependPolicy(name string, asn uint32, repeat uint32) error {
	// Statement that prepends ASN
	stmt := &api.Statement{
		Name: name,
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ACCEPT,
			AsPrepend: &api.AsPrependAction{
				Asn:    asn,
				Repeat: repeat,
			},
		},
	}

	// Policy that holds the statement
	gbgp.leaderPolicy = &api.Policy{
		Name:       name,
		Statements: []*api.Statement{stmt},
	}

	// Add the policy
	return gbgp.srv.AddPolicy(context.TODO(), &api.AddPolicyRequest{Policy: gbgp.leaderPolicy})
}

// EnablePrepend applies a global export policy that prepends ASN N times
func (gbgp *GoBGP) CreateFollowerPrependPolicy(name string, asn uint32, repeat uint32) error {
	// Statement that prepends ASN
	stmt := &api.Statement{
		Name: name,
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ACCEPT,
			AsPrepend: &api.AsPrependAction{
				Asn:    asn,
				Repeat: repeat,
			},
		},
	}

	// Policy that holds the statement
	gbgp.slavePolicy = &api.Policy{
		Name:       name,
		Statements: []*api.Statement{stmt},
	}

	// Add the policy
	return gbgp.srv.AddPolicy(context.TODO(), &api.AddPolicyRequest{Policy: gbgp.slavePolicy})
}

// SetLeaderPrependPolicy( removes the global prepend policy
func (gbgp *GoBGP) SetLeaderPrependPolicy() {
	if gbgp.leaderPolicy == nil {
		gbgp.logger.Warn("leader policy not created yet:", log.Fields{})
		return
	}
	// Remove the assignment
	err := gbgp.srv.SetPolicyAssignment(context.TODO(), &api.SetPolicyAssignmentRequest{
		//All: false, // all policy assignments -> cause  default deny
		Assignment: &api.PolicyAssignment{
			Name:          globalTableName,
			Policies:      []*api.Policy{gbgp.leaderPolicy},
			Direction:     api.PolicyDirection_EXPORT,
			DefaultAction: api.RouteAction_ACCEPT,
		},
	})
	if err != nil {
		gbgp.logger.Error(fmt.Sprintf("failed to set global leader prepend policy assignment: %v", err), log.Fields{})
		return
	}

	gbgp.logger.Debug("leader global prepend policy was set ", log.Fields{})
}

// SetSlavePrependPolicy - removes the global prepend policy
func (gbgp *GoBGP) SetSlavePrependPolicy() {
	if gbgp.slavePolicy == nil {
		gbgp.logger.Warn("slave policy not created yet:", log.Fields{})
		return
	}
	// Set the assignment
	err := gbgp.srv.SetPolicyAssignment(context.TODO(), &api.SetPolicyAssignmentRequest{
		//All: false, //all policy assignments -> cause  default deny
		Assignment: &api.PolicyAssignment{
			Name:          globalTableName,
			Policies:      []*api.Policy{gbgp.slavePolicy},
			Direction:     api.PolicyDirection_EXPORT,
			DefaultAction: api.RouteAction_ACCEPT,
		},
	})
	if err != nil {
		gbgp.logger.Error(fmt.Sprintf("failed to set global slave prepend policy assignment: %v", err), log.Fields{})
		return
	}

	gbgp.logger.Debug("follower global prepend policy was set", log.Fields{})
}

// SetFallbackPrependPolicy( removes the global prepend policy
func (gbgp *GoBGP) SetFallbackPrependPolicy() {
	// Set the assignment
	err := gbgp.srv.SetPolicyAssignment(context.TODO(), &api.SetPolicyAssignmentRequest{
		//All: false, // all policy assignments -> cause  default deny
		Assignment: &api.PolicyAssignment{
			Name:          globalTableName,
			Policies:      []*api.Policy{}, // No policy, so removing all existing => no AS path prepend
			Direction:     api.PolicyDirection_EXPORT,
			DefaultAction: api.RouteAction_ACCEPT,
		},
	})
	if err != nil {
		gbgp.logger.Error(fmt.Sprintf("failed to set global fallback prepend policy assignment: %v", err), log.Fields{})
		return
	}

	gbgp.logger.Debug("fallback global prepend policy was set", log.Fields{})
}
