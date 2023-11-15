//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	complete(errors.New("not implemented"))
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("not implemented")
}

func addPolicy(tb testing.TB, policies fakeResource[*Policy], params *policyParams) {
	tb.Helper()

	policy, _ := newIEGP(params)
	addIEGP(tb, policies, policy)
}

func addIEGP(tb testing.TB, policies fakeResource[*Policy], policy *v1.IsovalentEgressGatewayPolicy) {
	tb.Helper()

	policies.process(tb, resource.Event[*Policy]{
		Kind:   resource.Upsert,
		Object: policy,
	})
}

type policyParams struct {
	name              string
	endpointLabels    map[string]string
	destinationCIDR   string
	excludedCIDRs     []string
	nodeLabels        map[string]string
	iface             string
	egressIP          string
	maxGatewayNodes   int
	activeGatewayIPs  []string
	healthyGatewayIPs []string
}

func newIEGP(params *policyParams) (*Policy, *PolicyConfig) {
	// Note we avoid 'MustParse*()' varieties here to allow testing how
	// poor input is handed to ParseIEGP().
	parsedDestinationCIDR, _ := netip.ParsePrefix(params.destinationCIDR)

	parsedExcludedCIDRs := []netip.Prefix{}
	for _, excludedCIDR := range params.excludedCIDRs {
		parsedExcludedCIDR, _ := netip.ParsePrefix(excludedCIDR)
		parsedExcludedCIDRs = append(parsedExcludedCIDRs, parsedExcludedCIDR)
	}

	parsedActiveGatewayIPs := []netip.Addr{}
	for _, activeGatewayIP := range params.activeGatewayIPs {
		parsedActiveGatewayIPs = append(parsedActiveGatewayIPs, netip.MustParseAddr(activeGatewayIP))
	}

	parsedHealthyGatewayIPs := []netip.Addr{}
	for _, healthyGatewayIP := range params.healthyGatewayIPs {
		parsedHealthyGatewayIPs = append(parsedHealthyGatewayIPs, netip.MustParseAddr(healthyGatewayIP))
	}

	policy := &PolicyConfig{
		id: types.NamespacedName{
			Name: params.name,
		},
		dstCIDRs:      []netip.Prefix{parsedDestinationCIDR},
		excludedCIDRs: parsedExcludedCIDRs,
		endpointSelectors: []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		},
		groupConfigs: []groupConfig{
			{
				nodeSelector: api.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
				iface:           params.iface,
				maxGatewayNodes: params.maxGatewayNodes,
			},
		},
		groupStatuses: []groupStatus{
			{
				activeGatewayIPs:  parsedActiveGatewayIPs,
				healthyGatewayIPs: parsedHealthyGatewayIPs,
			},
		},
	}

	if len(params.endpointLabels) != 0 {
		policy.endpointSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		}
	}

	excludedCIDRs := []v1.IPv4CIDR{}
	for _, excludedCIDR := range params.excludedCIDRs {
		excludedCIDRs = append(excludedCIDRs, v1.IPv4CIDR(excludedCIDR))
	}

	iegp := &Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name: params.name,
		},
		Spec: v1.IsovalentEgressGatewayPolicySpec{
			Selectors: []v1.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
			},
			DestinationCIDRs: []v1.IPv4CIDR{
				v1.IPv4CIDR(params.destinationCIDR),
			},
			ExcludedCIDRs: excludedCIDRs,
			EgressGroups: []v1.EgressGroup{
				{
					NodeSelector: &slimv1.LabelSelector{
						MatchLabels: params.nodeLabels,
					},
					Interface:       params.iface,
					EgressIP:        params.egressIP,
					MaxGatewayNodes: params.maxGatewayNodes,
				},
			},
		},
		Status: v1.IsovalentEgressGatewayPolicyStatus{
			GroupStatuses: []v1.IsovalentEgressGatewayPolicyGroupStatus{
				{
					ActiveGatewayIPs:  params.activeGatewayIPs,
					HealthyGatewayIPs: params.healthyGatewayIPs,
				},
			},
		},
	}

	return iegp, policy
}

func addNode(tb testing.TB, nodes fakeResource[*cilium_api_v2.CiliumNode], node nodeTypes.Node) {
	nodes.process(tb, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node.ToCiliumNode(),
	})
}

type gatewayStatus struct {
	activeGatewayIPs  []string
	healthyGatewayIPs []string
}

func assertIegpGatewayStatus(tb testing.TB, fakeSet *k8sClient.FakeClientset, policyName string, gs gatewayStatus) {
	var err error
	for i := 0; i < 10; i++ {
		if err = tryAssertIegpGatewayStatus(tb, fakeSet, policyName, gs); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.Nil(tb, err)
}

func tryAssertIegpGatewayStatus(tb testing.TB, fakeSet *k8sClient.FakeClientset, policyName string, gs gatewayStatus) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), "policy-1", metav1.GetOptions{})
	if err != nil {
		return err
	}

	iegpGs := iegp.Status.GroupStatuses[0]

	if !cmp.Equal(gs.activeGatewayIPs, iegpGs.ActiveGatewayIPs, cmpopts.EquateEmpty()) {
		return fmt.Errorf("active gateway IPs don't match expected ones: %v vs expected %v", iegpGs.ActiveGatewayIPs, gs.activeGatewayIPs)
	}

	if !cmp.Equal(gs.healthyGatewayIPs, iegpGs.HealthyGatewayIPs, cmpopts.EquateEmpty()) {
		return fmt.Errorf("healthy gateway IPs don't match expected ones: %v vs expected %v", iegpGs.HealthyGatewayIPs, gs.healthyGatewayIPs)
	}

	return nil
}
