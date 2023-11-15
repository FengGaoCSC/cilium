// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

// OperatorCell provides an [OperatorManager] for consumption with hive.
var OperatorCell = cell.Module(
	"egressgatewayha-operator",
	"The Egress Gateway Operator manages cluster wide EGW state",
	cell.Config(defaultOperatorConfig),
	cell.Provide(NewEgressGatewayOperatorManager),
)

type OperatorConfig struct {
	// Amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration
}

var defaultOperatorConfig = OperatorConfig{
	2 * time.Second,
}

func (def OperatorConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

type OperatorParams struct {
	cell.In

	Config        OperatorConfig
	DaemonConfig  *option.DaemonConfig
	Clientset     k8sClient.Clientset
	Policies      resource.Resource[*Policy]
	Nodes         resource.Resource[*cilium_api_v2.CiliumNode]
	Healthchecker healthcheck.Healthchecker

	Lifecycle hive.Lifecycle
}

type OperatorManager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// clientset is a k8s clientset used to retrieve and update the IEGP
	// objects' status
	clientset k8sClient.Clientset

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// gatewayNodeDatatStore stores all nodes that are acting as a gateway
	gatewayNodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policies stores IEGPs indexed by policyID
	policyCache map[policyID]*Policy

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// healthchecker checks the health status of the nodes configured as
	// gateway by at least one policy
	healthchecker healthcheck.Healthchecker

	// reconciliationTrigger is the trigger used to reconcile the the egress
	// gateway policies statuses with the list of active and healthy gateway
	// IPs.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger
}

func NewEgressGatewayOperatorManager(p OperatorParams) (out struct {
	cell.Out

	*OperatorManager
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGateway && !dcfg.EnableIPv4EgressGatewayHA {
		return out, nil
	}

	out.OperatorManager = newEgressGatewayOperatorManager(p)

	return out, nil
}

func newEgressGatewayOperatorManager(p OperatorParams) *OperatorManager {
	operatorManager := &OperatorManager{
		clientset:            p.Clientset,
		policies:             p.Policies,
		ciliumNodes:          p.Nodes,
		nodeDataStore:        make(map[string]nodeTypes.Node),
		gatewayNodeDataStore: make(map[string]nodeTypes.Node),
		policyConfigs:        make(map[policyID]*PolicyConfig),
		policyCache:          make(map[policyID]*Policy),
		healthchecker:        p.Healthchecker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			t, err := trigger.NewTrigger(trigger.Parameters{
				Name:        "egress_gateway_ha_operator_reconciliation",
				MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
				TriggerFunc: func(reasons []string) {
					reason := strings.Join(reasons, ", ")
					log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

					operatorManager.Lock()
					defer operatorManager.Unlock()

					operatorManager.reconcileLocked()
				},
			})
			if err != nil {
				return err
			}

			operatorManager.reconciliationTrigger = t

			go operatorManager.processEvents(ctx)
			operatorManager.startHealthcheckingLoop()

			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			cancel()
			return nil
		},
	})

	return operatorManager
}

func (operatorManager *OperatorManager) processEvents(ctx context.Context) {
	var policySync, nodeSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync {
			return
		}

		operatorManager.Lock()
		defer operatorManager.Unlock()

		if operatorManager.allCachesSynced {
			return
		}

		operatorManager.allCachesSynced = true
		operatorManager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	policyEvents := operatorManager.policies.Events(ctx)
	nodeEvents := operatorManager.ciliumNodes.Events(ctx)

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
				operatorManager.handlePolicyEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				operatorManager.handleNodeEvent(event)
			}
		}
	}
}

// startHealthcheckingLoop spawns a goroutine that periodically checks if the
// health status of any node has changed, and when that's the case, it re runs
// the reconciliation.
func (operatorManager *OperatorManager) startHealthcheckingLoop() {
	go func() {
		for range operatorManager.healthchecker.Events() {
			operatorManager.reconciliationTrigger.TriggerWithReason("healthcheck event")
		}
	}()
}

func (operatorManager *OperatorManager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := operatorManager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		operatorManager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (operatorManager *OperatorManager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithFields(logrus.Fields{
		logfields.IsovalentEgressGatewayPolicyName: policy.ObjectMeta.Name,
		logfields.K8sUID: policy.ObjectMeta.UID,
	})

	config, err := ParseIEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse IsovalentEgressGatewayPolicy")
		return err
	}

	if _, ok := operatorManager.policyCache[config.id]; !ok {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
	}

	operatorManager.policyCache[config.id] = policy
	operatorManager.policyConfigs[config.id] = config
	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (operatorManager *OperatorManager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseIEGPConfigID(policy)

	operatorManager.Lock()
	defer operatorManager.Unlock()

	logger := log.WithField(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	if operatorManager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
		return
	}

	logger.Debug("Deleted IsovalentEgressGatewayPolicy")
	delete(operatorManager.policyCache, configID)
	delete(operatorManager.policyConfigs, configID)

	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy deleted")
}

// handleNodeEvent takes care of node upserts and removals.
func (operatorManager *OperatorManager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	operatorManager.Lock()
	defer operatorManager.Unlock()

	if event.Kind == resource.Upsert {
		operatorManager.nodeDataStore[node.Name] = node
		operatorManager.onChangeNodeLocked("CiliumNode updated")
	} else {
		delete(operatorManager.nodeDataStore, node.Name)
		operatorManager.onChangeNodeLocked("CiliumNode deleted")
	}
}

func (operatorManager *OperatorManager) onChangeNodeLocked(event string) {
	operatorManager.nodes = []nodeTypes.Node{}
	for _, n := range operatorManager.nodeDataStore {
		operatorManager.nodes = append(operatorManager.nodes, n)
	}
	sort.Slice(operatorManager.nodes, func(i, j int) bool {
		return operatorManager.nodes[i].Name < operatorManager.nodes[j].Name
	})

	operatorManager.reconciliationTrigger.TriggerWithReason(event)
}

func (operatorManager *OperatorManager) nodeIsHealthy(nodeName string) bool {
	return operatorManager.healthchecker.NodeIsHealthy(nodeName)
}

func (operatorManager *OperatorManager) regenerateGatewayNodesList() {
	nodes := map[string]nodeTypes.Node{}

	for _, policyConfig := range operatorManager.policyConfigs {
		for _, gc := range policyConfig.groupConfigs {
			for _, n := range operatorManager.nodes {
				if gc.selectsNodeAsGateway(n) {
					nodes[n.Name] = n
				}
			}
		}
	}

	operatorManager.gatewayNodeDataStore = nodes
}

func (operatorManager *OperatorManager) updatePolicesGroupStatuses() {
	for _, config := range operatorManager.policyConfigs {
		err := config.updateGroupStatuses(operatorManager)
		if err != nil {
			operatorManager.reconciliationTrigger.TriggerWithReason("retry after error")
		}
	}
}

// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (operatorManager *OperatorManager) reconcileLocked() {
	if !operatorManager.allCachesSynced {
		return
	}

	operatorManager.regenerateGatewayNodesList()
	operatorManager.healthchecker.UpdateNodeList(operatorManager.gatewayNodeDataStore)

	operatorManager.updatePolicesGroupStatuses()
}
