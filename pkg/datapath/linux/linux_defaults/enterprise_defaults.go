// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_defaults

const (
	// RouteTableEgressGatewayHAInterfacesOffset is the offset for the per-ENI
	// egress gateway routing tables.
	// This will cause collisions after 1000 ENI interfaces have been created.
	RouteTableEgressGatewayHAInterfacesOffset = RouteTableEgressGatewayInterfacesOffset + 1000

	// RulePriorityEgressGatewayHA is the priority used in IP routes added by the
	// HA Egress Gateway. It's chosen to run after the regular egress code, which
	// is what happens in the datapath as well.
	RulePriorityEgressGatewayHA = RulePriorityEgressGateway - 1
)
