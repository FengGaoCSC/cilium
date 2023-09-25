//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	_ "embed"
	"fmt"
	"net"

	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

type EnterpriseTest struct {
	*check.Test

	ctx *EnterpriseConnectivityTest

	// Isovalent Egress Gateway Policies active during this test.
	iegps map[string]*isovalentv1.IsovalentEgressGatewayPolicy
}

func (t *EnterpriseTest) Context() *EnterpriseConnectivityTest {
	return t.ctx
}

const (
	NoExcludedCIDRs = iota
	ExternalNodeExcludedCIDRs
)

// IsovalentEgressGatewayPolicyParams is used to configure how an IsovalentEgressGatewayPolicy template should be
// configured before being applied.
type IsovalentEgressGatewayPolicyParams struct {
	// ExcludedCIDRs controls how the ExcludedCIDRs property should be configured
	ExcludedCIDRs int
}

// WithIsovalentEgressGatewayPolicy takes a string containing a YAML policy
// document and adds the cilium egress gateway polic(y)(ies) to the scope of the
// Test, to be applied when the test starts running. When calling this method,
// note that the egress gateway enabled feature requirement is applied directly
// here.
func (t *EnterpriseTest) WithIsovalentEgressGatewayPolicy(policy string, params IsovalentEgressGatewayPolicyParams) *EnterpriseTest {
	pl, err := parseIsovalentEgressGatewayPolicyYAML(policy)
	if err != nil {
		t.Fatalf("Parsing policy YAML: %s", err)
	}

	for i := range pl {
		// Change the default test namespace as required.
		for _, k := range []string{
			k8sConst.PodNamespaceLabel,
			check.KubernetesSourcedLabelPrefix + k8sConst.PodNamespaceLabel,
			check.AnySourceLabelPrefix + k8sConst.PodNamespaceLabel,
		} {
			for _, e := range pl[i].Spec.Selectors {
				ps := e.PodSelector
				if n, ok := ps.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					ps.MatchLabels[k] = t.Test.Context().Params().TestNamespace
				}
			}
		}

		// Set the egress gateway node
		egressGatewayNode := t.EgressGatewayNode()
		if egressGatewayNode == "" {
			t.Fatalf("Cannot find egress gateway node")
		}

		for j := range pl[i].Spec.EgressGroups {
			pl[i].Spec.EgressGroups[j].NodeSelector.MatchLabels["kubernetes.io/hostname"] = egressGatewayNode
		}

		// Set the excluded CIDRs
		pl[i].Spec.ExcludedCIDRs = []isovalentv1.IPv4CIDR{}

		switch params.ExcludedCIDRs {
		case ExternalNodeExcludedCIDRs:
			for _, nodeWithoutCiliumIP := range t.Context().Params().NodesWithoutCiliumIPs {
				if parsedIP := net.ParseIP(nodeWithoutCiliumIP.IP); parsedIP.To4() == nil {
					continue
				}

				cidr := isovalentv1.IPv4CIDR(fmt.Sprintf("%s/32", nodeWithoutCiliumIP.IP))
				pl[i].Spec.ExcludedCIDRs = append(pl[i].Spec.ExcludedCIDRs, cidr)
			}
		}
	}

	if err := t.addIEGPs(pl...); err != nil {
		t.Fatalf("Adding IEGPs to cilium egress gateway policy context: %s", err)
	}

	t.WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.EgressGatewayHA))

	return t
}

func (t *EnterpriseTest) WithScenarios(sl ...check.Scenario) *EnterpriseTest {
	t.Test.WithScenarios(sl...)

	return t
}

func (t *EnterpriseTest) setup(ctx context.Context) error {
	if err := t.applyPolicies(ctx); err != nil {
		t.CiliumLogs(ctx)
		return fmt.Errorf("applying policies: %w", err)
	}

	return nil
}
