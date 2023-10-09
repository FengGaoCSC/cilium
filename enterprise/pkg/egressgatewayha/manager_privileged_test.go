// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	testInterface1 = "cilium_egwha1"
	testInterface2 = "cilium_egwha2"

	node1 = "k8s1"
	node2 = "k8s2"

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"

	destCIDR        = "1.1.1.0/24"
	destIP          = "1.1.1.1"
	allZeroDestCIDR = "0.0.0.0/0"
	excludedCIDR1   = "1.1.1.22/32"
	excludedCIDR2   = "1.1.1.240/30"
	excludedCIDR3   = "1.1.1.0/28"

	egressIP1   = "192.168.101.1"
	egressCIDR1 = "192.168.101.1/24"

	egressIP2   = "192.168.102.1"
	egressCIDR2 = "192.168.102.1/24"

	zeroIP4 = "0.0.0.0"

	// Special values for gatewayIP, see pkg/egressgateway/manager.go
	gatewayNotFoundValue     = "0.0.0.0"
	gatewayExcludedCIDRValue = "0.0.0.1"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	noNodeGroup       = map[string]string{}
	nodeGroup1Labels  = map[string]string{"label1": "1"}
	nodeGroup2Labels  = map[string]string{"label2": "2"}
	nodeGroup12Labels = map[string]string{"label1": "1", "label2": "2"}
)

type egressRule struct {
	sourceIP  string
	destCIDR  string
	egressIP  string
	gatewayIP string
}

type parsedEgressRule struct {
	sourceIP  net.IP
	destCIDR  net.IPNet
	egressIP  net.IP
	gatewayIP net.IP
}

type egressCtEntry struct {
	// ignoring sport, dport, etc for now
	sourceIP  string
	destIP    string
	gatewayIP string
}

type parsedEgressCtEntry struct {
	sourceIP  net.IP
	destIP    net.IP
	gatewayIP net.IP
}

type healthcheckerMock struct {
	nodes  map[string]struct{}
	events chan healthcheck.Event
}

func (h *healthcheckerMock) UpdateNodeList(nodes map[string]nodeTypes.Node) {
}

func (h *healthcheckerMock) NodeIsHealthy(nodeName string) bool {
	_, ok := h.nodes[nodeName]
	return ok
}

func (h *healthcheckerMock) Events() chan healthcheck.Event {
	return h.events
}

func (h *healthcheckerMock) healthy(nodeName string) {
	h.nodes[nodeName] = struct{}{}
}

func (h *healthcheckerMock) unhealthy(nodeName string) {
	delete(h.nodes, nodeName)
}

func newHealthcheckerMock() *healthcheckerMock {
	return &healthcheckerMock{
		nodes:  make(map[string]struct{}),
		events: make(chan healthcheck.Event),
	}
}

// Hook up gocheck into the "go test" runner.
type EgressGatewayTestSuite struct {
	manager     *Manager
	policies    fakeResource[*Policy]
	cacheStatus k8s.CacheStatus
	healthcheck *healthcheckerMock
}

var _ = Suite(&EgressGatewayTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressGatewayTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)

	nodeTypes.SetName(node1)
}

func (k *EgressGatewayTestSuite) SetUpTest(c *C) {
	k.cacheStatus = make(k8s.CacheStatus)
	k.policies = make(fakeResource[*Policy])
	k.healthcheck = newHealthcheckerMock()

	lc := hivetest.Lifecycle(c)
	policyMap := egressmapha.CreatePrivatePolicyMap(lc, egressmapha.DefaultPolicyConfig)
	ctMap := egressmapha.CreatePrivateCtMap(lc)

	var err error
	k.manager, err = newEgressGatewayManager(Params{
		Lifecycle:         lc,
		Config:            Config{true, 1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		CacheStatus:       k.cacheStatus,
		IdentityAllocator: identityAllocator,
		PolicyMap:         policyMap,
		CtMap:             ctMap,
		Policies:          k.policies,
		Healthchecker:     k.healthcheck,
	})
	c.Assert(err, IsNil)
	c.Assert(k.manager, NotNil)
}

func (k *EgressGatewayTestSuite) TestEgressGatewayIEGPParser(c *C) {
	// must specify name
	policy := policyParams{
		name:            "",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ := newIEGP(&policy)
	_, err := ParseIEGP(iegp)
	c.Assert(err, NotNil)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.DestinationCIDRs = nil
	_, err = ParseIEGP(iegp)
	c.Assert(err, NotNil)

	// must specify at least one DestinationCIDR
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(iegp)
	c.Assert(err, NotNil)

	// catch nil EgressGroups field
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.EgressGroups = nil
	_, err = ParseIEGP(iegp)
	c.Assert(err, NotNil)

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.Selectors[0].NamespaceSelector = nil
	iegp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseIEGP(iegp)
	c.Assert(err, NotNil)

	// can't specify both egress iface and IP
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
		egressIP:        egressIP1,
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(iegp)
	c.Assert(err, NotNil)
}

func (k *EgressGatewayTestSuite) TestEgressGatewayManagerHAGroup(c *C) {
	createTestInterface(c, testInterface1, egressCIDR1)
	createTestInterface(c, testInterface2, egressCIDR2)

	policyMap := k.manager.policyMap
	egressGatewayManager := k.manager

	k.healthcheck.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}

	close(k.cacheStatus)
	k.policies.sync(c)

	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	node2 := newCiliumNode(node2, node2IP, nodeGroup1Labels)
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	}

	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{})

	// Add a new endpoint which matches policy-1
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Make k8s1 unhealthy
	k.healthcheck.unhealthy("k8s1")
	forceReconcile(k.manager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Remove k8s1 from node-group-1
	node1.Labels = noNodeGroup
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP},
	})

	// Add back node1
	node1.Labels = nodeGroup1Labels
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// And make it healthy
	k.healthcheck.healthy("k8s1")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Make k8s2 unhealthy
	k.healthcheck.unhealthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Remove k8s2 from node-group-1
	node2.Labels = noNodeGroup
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Add back k8s2
	node2.Labels = nodeGroup1Labels
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// And make it healthy
	k.healthcheck.healthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Update the EP labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	egressGatewayManager.OnUpdateEndpoint(&ep1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{})

	// Add back the endpoint
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Update the policy group config to match node-group-2
	policy1.nodeLabels = nodeGroup2Labels
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{})

	// Change it back to node-group-1
	policy1.nodeLabels = nodeGroup1Labels
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Update the policy group config to allow at most 1 gateway at a time
	policy1.maxGatewayNodes = 1
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Make k8s1 unhealthy
	k.healthcheck.unhealthy("k8s1")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Remove k8s1 from node-group-1
	node1.Labels = noNodeGroup
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP},
	})

	// Add back node1
	node1.Labels = nodeGroup1Labels
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	// And make it healthy
	k.healthcheck.healthy("k8s1")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Clear the maxGatewayNodes policy property
	policy1.maxGatewayNodes = 0
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Changing the DestCIDR to 0.0.0.0 results in a conflict with
	// the existing IP rules. Test that the manager is able to
	// resolve this conflict.
	policy1.destinationCIDR = allZeroDestCIDR
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, allZeroDestCIDR, egressIP1, node1IP},
		{ep1IP, allZeroDestCIDR, egressIP1, node2IP},
	})

	// Restore old DestCIDR
	policy1.destinationCIDR = destCIDR
	addPolicy(c, k.policies, policy1)

	// Create a new policy
	policy2 := &policyParams{
		name:            "policy-2",
		endpointLabels:  ep2Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup2Labels,
		iface:           testInterface2,
	}
	addPolicy(c, k.policies, policy2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Add k8s1 to node-group-2 egress group
	node1.Labels = nodeGroup12Labels
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Add a new endpoint that matches policy-2
	ep2, id2 := newEndpointAndIdentity("ep-2", ep2IP, ep2Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
	})

	// Add also k8s2 to node-group-2 egress group
	node2.Labels = nodeGroup12Labels
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Test excluded CIDRs by adding one to policy-1
	policy1.excludedCIDRs = []string{excludedCIDR1}
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Add a second excluded CIDR to policy-1
	policy1.excludedCIDRs = []string{excludedCIDR1, excludedCIDR2}
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Remove the first excluded CIDR from policy-1
	policy1.excludedCIDRs = []string{excludedCIDR2}
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Remove the second excluded CIDR
	policy1.excludedCIDRs = nil
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Remove k8s1 from node-group-1 (but keep it in node-group-2)
	node1.Labels = nodeGroup2Labels
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Update the EP 1 labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	egressGatewayManager.OnUpdateEndpoint(&ep1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Update the EP 2 labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep2, id2, map[string]string{})
	egressGatewayManager.OnUpdateEndpoint(&ep2)
	waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, policyMap, []egressRule{})
}

func (k *EgressGatewayTestSuite) TestEgressGatewayManagerCtEntries(c *C) {
	createTestInterface(c, testInterface1, egressCIDR1)

	egressGatewayManager := k.manager

	k.healthcheck.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}

	close(k.cacheStatus)
	k.policies.sync(c)

	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	egressGatewayManager.OnUpdateNode(node1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	node2 := newCiliumNode(node2, node2IP, nodeGroup1Labels)
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{})
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Create a new HA policy based on a group config
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	}
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{})
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Add a new endpoint which matches policy-1
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	/* Scenario:
	 * 1. A gateway becomes unhealthy. Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	insertEgressCtEntry(c, k.manager.ctMap, ep1IP, destIP, node2IP)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Make k8s2 unhealthy
	k.healthcheck.unhealthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry is gone:
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Make k8s2 healthy again
	k.healthcheck.healthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A gateway is no longer selected by the policy's labels.
	 *    Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	insertEgressCtEntry(c, k.manager.ctMap, ep1IP, destIP, node2IP)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Remove k8s2 from node-group-1
	node2.Labels = noNodeGroup
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Add back k8s2
	node2.Labels = nodeGroup1Labels
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. Make the gateway unhealthy.
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	insertEgressCtEntry(c, k.manager.ctMap, ep1IP, destIP, node2IP)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	policy1.maxGatewayNodes = 1
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should still exist, as k8s2 is healthy
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Make k8s2 unhealthy
	k.healthcheck.unhealthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Make k8s2 healthy again
	k.healthcheck.healthy("k8s2")
	forceReconcile(egressGatewayManager, eventHealthcheck)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	policy1.maxGatewayNodes = 0
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. De-select the gateway from the policy
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	insertEgressCtEntry(c, k.manager.ctMap, ep1IP, destIP, node2IP)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	policy1.maxGatewayNodes = 1
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should still exist, as k8s2 is healthy
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Remove k8s2 from node-group-1
	node2.Labels = noNodeGroup
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Add back k8s2
	node2.Labels = nodeGroup1Labels
	egressGatewayManager.OnUpdateNode(node2)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	policy1.maxGatewayNodes = 0
	addPolicy(c, k.policies, policy1)
	reconciliationEventsCount = waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A policy changes and a CT entry is now matched by an excluded CIDR
	 *    (the CT entry should now expire)
	 */

	insertEgressCtEntry(c, k.manager.ctMap, ep1IP, destIP, node2IP)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Add the destination IP to the policy excluded CIDRs list
	policy1.excludedCIDRs = []string{excludedCIDR3}
	addPolicy(c, k.policies, policy1)
	waitForReconciliationRun(c, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(c, k.manager.policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR3, egressIP1, gatewayExcludedCIDRValue},
	})

	assertEgressCtEntries(c, k.manager.ctMap, []egressCtEntry{})
}

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate()
	if err != nil {
		t.Fatal(err)
	}
}

func createTestInterface(tb testing.TB, iface string, addr string) {
	tb.Helper()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		tb.Fatal(err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Error(err)
		}
	})

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatal(err)
	}

	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(link, a); err != nil {
		tb.Fatal(err)
	}
}

func waitForReconciliationRun(tb testing.TB, egressGatewayManager *Manager, currentRun uint64) uint64 {
	for i := 0; i < 100; i++ {
		count := egressGatewayManager.reconciliationEventsCount.Load()
		if count > currentRun {
			return count
		}

		time.Sleep(10 * time.Millisecond)
	}

	tb.Fatal("Reconciliation is taking too long to run")
	return 0
}

func newCiliumNode(name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	return nodeTypes.Node{
		Name:   name,
		Labels: nodeLabels,
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(nodeIP),
			},
		},
	}
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentity(name, ip string, epLabels map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(epLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
		},
		Identity: &v2.EndpointIdentity{
			ID: int64(id.ID),
		},
		Networking: &v2.EndpointNetworking{
			Addressing: v2.AddressPairList{
				&v2.AddressPair{
					IPV4: ip,
				},
			},
		},
	}, id
}

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	ctx := context.Background()

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, labels.Map2Labels(newEpLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	return newID
}
func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string) parsedEgressRule {
	sip := net.ParseIP(sourceIP)
	if sip == nil {
		panic("Invalid source IP")
	}

	_, dc, err := net.ParseCIDR(destCIDR)
	if err != nil {
		panic("Invalid destination CIDR")
	}

	eip := net.ParseIP(egressIP)
	if eip == nil {
		panic("Invalid egress IP")
	}

	gip := net.ParseIP(gatewayIP)
	if gip == nil {
		panic("Invalid gateway IP")
	}

	return parsedEgressRule{
		sourceIP:  sip,
		destCIDR:  *dc,
		egressIP:  eip,
		gatewayIP: gip,
	}
}

func assertEgressRules(c *C, policyMap egressmapha.PolicyMap, rules []egressRule) {
	c.Helper()

	err := tryAssertEgressRules(policyMap, rules)
	c.Assert(err, IsNil)
}

func tryAssertEgressRules(policyMap egressmapha.PolicyMap, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if !policyVal.GetEgressIP().Equal(r.egressIP) {
			return fmt.Errorf("policy egress IP %s doesn't match rule egress IP %s", policyVal.GetEgressIP(), r.egressIP)
		}

		if r.gatewayIP.Equal(net.ParseIP(zeroIP4)) {
			if policyVal.Size != 0 {
				return fmt.Errorf("policy size is %d even though no gateway is set", policyVal.Size)
			}
		} else {
			gwFound := false
			for _, policyGatewayIP := range policyVal.GetGatewayIPs() {
				if policyGatewayIP.Equal(r.gatewayIP) {
					gwFound = true
					break
				}
			}
			if !gwFound {
				return fmt.Errorf("missing gateway %s in policy", r.gatewayIP)
			}
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {

		nextPolicyGateway:
			for _, gatewayIP := range val.GetGatewayIPs() {
				for _, r := range parsedRules {
					if key.Match(r.sourceIP, &r.destCIDR) {
						if val.GetEgressIP().Equal(r.egressIP) && gatewayIP.Equal(r.gatewayIP) {
							continue nextPolicyGateway
						}
					}
				}

				untrackedRule = true
				return
			}
		},
	)

	if untrackedRule {
		return fmt.Errorf("Untracked egress policy")
	}

	return nil
}

func parseEgressCtEntry(sourceIP, destIP, gatewayIP string) parsedEgressCtEntry {
	sip := net.ParseIP(sourceIP)
	if sip == nil {
		panic("Invalid source IP")
	}

	dip := net.ParseIP(destIP)
	if dip == nil {
		panic("Invalid destination IP")
	}

	gip := net.ParseIP(gatewayIP)
	if gip == nil {
		panic("Invalid gateway IP")
	}

	return parsedEgressCtEntry{
		sourceIP:  sip,
		destIP:    dip,
		gatewayIP: gip,
	}
}

func assertEgressCtEntries(tb testing.TB, ctMap egressmapha.CtMap, entries []egressCtEntry) {
	tb.Helper()

	err := tryAssertEgressCtEntries(tb, ctMap, entries)
	require.NoError(tb, err)
}

func tryAssertEgressCtEntries(tb testing.TB, ctMap egressmapha.CtMap, entries []egressCtEntry) error {
	parsedEntries := []parsedEgressCtEntry{}
	for _, e := range entries {
		parsedEntries = append(parsedEntries, parseEgressCtEntry(e.sourceIP, e.destIP, e.gatewayIP))
	}

	for _, e := range parsedEntries {
		var val egressmapha.EgressCtVal4

		key := &egressmapha.EgressCtKey4{
			TupleKey4: tuple.TupleKey4{
				DestPort:   0,
				SourcePort: 0,
				NextHeader: u8proto.TCP,
				Flags:      0,
			},
		}

		copy(key.DestAddr[:], e.destIP.To4())
		copy(key.SourceAddr[:], e.sourceIP.To4())

		err := ctMap.Lookup(key, &val)
		if err != nil {
			return err
		}

		if !val.Gateway.IP().Equal(e.gatewayIP) {
			return fmt.Errorf("%v doesn't match %v", val.Gateway.IP(), e.gatewayIP)
		}
	}

	var err error
	ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			for _, e := range parsedEntries {
				if key.DestAddr.IP().Equal(e.destIP) && key.SourceAddr.IP().Equal(e.sourceIP) && val.Gateway.IP().Equal(e.gatewayIP) {
					return
				}
			}

			err = fmt.Errorf("untracked egress CT entry: from %v to %v via %v", key.SourceAddr.IP(), key.DestAddr.IP(), val.Gateway.IP())
		})

	return err
}

func insertEgressCtEntry(c *C, ctMap egressmapha.CtMap, sourceIP, destIP, gatewayIP string) {
	entry := parseEgressCtEntry(sourceIP, destIP, gatewayIP)

	key := &egressmapha.EgressCtKey4{
		TupleKey4: tuple.TupleKey4{
			DestPort:   0,
			SourcePort: 0,
			NextHeader: u8proto.TCP,
			Flags:      0,
		},
	}

	copy(key.DestAddr[:], entry.destIP.To4())
	copy(key.SourceAddr[:], entry.sourceIP.To4())

	val := &egressmapha.EgressCtVal4{}
	copy(val.Gateway[:], entry.gatewayIP.To4())

	err := ctMap.Update(key, val, 0)
	c.Assert(err, IsNil)
}

func forceReconcile(manager *Manager, event eventType) {
	manager.Lock()
	defer manager.Unlock()

	manager.setEventBitmap(event)
	manager.reconcileLocked()
}
