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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway-ha")
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.MustParseAddr("0.0.0.0")
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgatewayha",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
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
	// Install egress gateway IP rules and routes in order to properly steer
	// egress gateway traffic to the correct ENI interface.
	// Deprecated, has no effect, and will removed in v1.16"
	InstallEgressGatewayHARoutes bool

	// Healthcheck timeout after which an egress gateway is marked not healthy.
	// This also configures the frequency of probes to a value of healthcheckTimeout / 2
	// Deprecated, has no effect, and will removed in v1.16"
	EgressGatewayHAHealthcheckTimeout time.Duration

	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	InstallEgressGatewayHARoutes:                 false,
	EgressGatewayHAHealthcheckTimeout:            1 * time.Second,
	EgressGatewayHAReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("install-egress-gateway-ha-routes", def.InstallEgressGatewayHARoutes, "Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface")
	flags.MarkDeprecated("install-egress-gateway-ha-routes", "This option is deprecated, has no effect, and will be removed in v1.16")
	flags.Duration("egress-gateway-ha-healthcheck-timeout", def.EgressGatewayHAHealthcheckTimeout, "Healthcheck timeout after which an egress gateway is marked not healthy. This also configures the frequency of probes to a value of healthcheckTimeout / 2")
	flags.MarkDeprecated("egress-gateway-ha-healthcheck-timeout", "This option is deprecated, has no effect, and will be removed in v1.16")

	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// pendingEndpointEvents stores the k8s CiliumEndpoint add/update events
	// which still need to be processed by the manager, either because we
	// just received the event, or because the processing failed due to the
	// manager being unable to resolve the endpoint identity to a set of
	// labels
	pendingEndpointEvents map[endpointID]*k8sTypes.CiliumEndpoint

	// pendingEndpointEventsLock protects the access to the
	// pendingEndpointEvents map
	pendingEndpointEventsLock lock.RWMutex

	// endpointEventsQueue is a workqueue of CiliumEndpoint IDs that need to
	// be processed by the manager
	endpointEventsQueue workqueue.RateLimitingInterface

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap communicates the active policies to the dapath.
	policyMap egressmapha.PolicyMap

	// ctMap stores EGW specific conntrack entries.
	ctMap egressmapha.CtMap

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
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

	localNodeStore *node.LocalNodeStore
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	CacheStatus       k8s.CacheStatus
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmapha.PolicyMap
	Policies          resource.Resource[*Policy]
	CtMap             egressmapha.CtMap
	LocalNodeStore    *node.LocalNodeStore

	Lifecycle hive.Lifecycle
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EgressGatewayHAEnabled() {
		return out, nil
	}

	if dcfg.IdentityAllocationMode == option.IdentityAllocationModeKVstore {
		return out, errors.New("egress gateway is not supported in KV store identity allocation mode")
	}

	if dcfg.EnableHighScaleIPcache {
		return out, errors.New("egress gateway is not supported in high scale IPcache mode")
	}

	if !dcfg.MasqueradingEnabled() || !dcfg.EnableBPFMasquerade {
		return out, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	if !dcfg.EnableRemoteNodeIdentity {
		// datapath code depends on remote node identities to distinguish between
		// cluster-local and cluster-egress traffic.
		return out, fmt.Errorf("egress gateway requires remote node identities (--%s=\"true\")", option.EnableRemoteNodeIdentity)
	}

	if dcfg.EnableL7Proxy {
		log.WithField(logfields.URL, "https://github.com/cilium/cilium/issues/19642").
			Warningf("both egress gateway and L7 proxy (--%s) are enabled. This is currently not fully supported: "+
				"if the same endpoint is selected both by an egress gateway and a L7 policy, endpoint traffic will not go through egress gateway.", option.EnableL7Proxy)
	}

	if !p.DaemonConfig.HealthCheckingEnabled() {
		return out, fmt.Errorf("egress gateway HA requires healthchecking to be enabled")
	}

	if err := deleteStaleIPRulesAndRoutes(); err != nil {
		err = fmt.Errorf("cannot delete stale IP rules and routes: %w", err)
		return out, err
	}

	out.Manager, err = newEgressGatewayManager(p)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY_HA": "1",
	}

	return out, nil
}

func newEgressGatewayManager(p Params) (*Manager, error) {
	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	rateLimiter := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)
	endpointEventRetryQueue := workqueue.NewRateLimitingQueueWithConfig(rateLimiter, workqueue.RateLimitingQueueConfig{})

	manager := &Manager{
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP:       make(map[string][]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		pendingEndpointEvents:         make(map[endpointID]*k8sTypes.CiliumEndpoint),
		endpointEventsQueue:           endpointEventRetryQueue,
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
		policyMap:                     p.PolicyMap,
		policies:                      p.Policies,
		ctMap:                         p.CtMap,
		localNodeStore:                p.LocalNodeStore,
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_ha_reconciliation",
		MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
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
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			if probes.HaveLargeInstructionLimit() != nil {
				return fmt.Errorf("egress gateway needs kernel 5.2 or newer")
			}

			go manager.processEvents(ctx, p.CacheStatus)
			manager.processCiliumEndpoints(ctx, &wg)

			return nil
		},
		OnStop: func(hc hive.HookContext) error {
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
		return nil, fmt.Errorf("failed to wait for initial global identities: %v", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context, cacheStatus k8s.CacheStatus) {
	var globalSync, policySync bool
	maybeTriggerReconcile := func() {
		if !globalSync || !policySync {
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

	policyEvents := manager.policies.Events(ctx)
	for {
		select {
		case <-ctx.Done():
			return

		case <-cacheStatus:
			globalSync = true
			maybeTriggerReconcile()
			cacheStatus = nil

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
			}
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

// processCiliumEndpoints spawns a goroutine that:
//   - consumes the endpoint IDs returned by the endpointEventsQueue workqueue
//   - processes the CiliumEndpoints stored in pendingEndpointEvents for these
//     endpoint IDs
//   - in case the endpoint ID -> labels resolution fails, it adds back the
//     event to the workqueue so that it can be retried with an exponential
//     backoff
func (manager *Manager) processCiliumEndpoints(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		retryQueue := manager.endpointEventsQueue
		go func() {
			select {
			case <-ctx.Done():
				retryQueue.ShutDown()
			}
		}()

		for {
			item, shutdown := retryQueue.Get()
			if shutdown {
				break
			}
			endpointID := item.(types.NamespacedName)

			manager.pendingEndpointEventsLock.RLock()
			ep, ok := manager.pendingEndpointEvents[endpointID]
			manager.pendingEndpointEventsLock.RUnlock()

			var err error
			if ok {
				err = manager.addEndpoint(ep)
			} else {
				manager.deleteEndpoint(endpointID)
			}

			if err != nil {
				// if the endpoint event is still pending it means the manager
				// failed to resolve the endpoint ID to a set of labels, so add back
				// the item to the queue
				manager.endpointEventsQueue.AddRateLimited(endpointID)
			} else {
				// otherwise just remove it
				manager.endpointEventsQueue.Forget(endpointID)
			}

			manager.endpointEventsQueue.Done(endpointID)
		}
	}()
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithFields(logrus.Fields{
		logfields.IsovalentEgressGatewayPolicyName: policy.Name,
		logfields.K8sUID: policy.UID,
	})

	if policy.Status.ObservedGeneration != policy.GetGeneration() {
		logger.Debug("Received policy whose GroupStatuses has not yet been updated by the operator, ignoring it")
		return nil
	}

	config, err := ParseIEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse IsovalentEgressGatewayPolicy")
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
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
	configID := ParseIEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
	}

	logger.Debug("Deleted IsovalentEgressGatewayPolicy")

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
	})

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
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

func (manager *Manager) deleteEndpoint(id types.NamespacedName) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: id.Name,
		logfields.K8sNamespace:    id.Namespace,
	})

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, id)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	manager.pendingEndpointEventsLock.Lock()
	manager.pendingEndpointEvents[id] = endpoint
	manager.pendingEndpointEventsLock.Unlock()

	manager.endpointEventsQueue.Add(id)
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	manager.pendingEndpointEventsLock.Lock()
	delete(manager.pendingEndpointEvents, id)
	manager.pendingEndpointEventsLock.Unlock()

	manager.endpointEventsQueue.Add(id)
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

func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmapha.EgressPolicyKey4]egressmapha.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		policyKey := egressmapha.NewEgressPolicyKey4(endpointIP, dstCIDR)
		policyVal, policyPresent := egressPolicies[policyKey]

		activeGatewayIPs := gwc.activeGatewayIPs
		if excludedCIDR {
			activeGatewayIPs = []netip.Addr{ExcludedCIDRIPv4}
		}

		if policyPresent && policyVal.Match(gwc.egressIP, activeGatewayIPs) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP,
			logfields.GatewayIPs:      joinStringers(activeGatewayIPs, ","),
		})

		if err := egressmapha.ApplyEgressPolicy(manager.policyMap, endpointIP, dstCIDR, gwc.egressIP, activeGatewayIPs); err != nil {
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
// is not baked by an actual k8s IsovalentEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmapha.EgressPolicyKey4]egressmapha.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

nextPolicyKey:
	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) bool {
			activeGatewayIPs := gwc.activeGatewayIPs
			if excludedCIDR {
				activeGatewayIPs = []netip.Addr{ExcludedCIDRIPv4}
			}

			return policyKey.Match(endpointIP, dstCIDR) && policyVal.Match(gwc.egressIP, activeGatewayIPs)
		}

		if manager.policyMatches(policyKey.GetSourceIP(), matchPolicy) {
			continue nextPolicyKey
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressIP(),
			logfields.GatewayIPs:      joinStringers(policyVal.GetGatewayIPs(), ","),
		})

		if err := egressmapha.RemoveEgressPolicy(manager.policyMap, policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy removed")
		}
	}
}

func (manager *Manager) removeExpiredCtEntries() {
	ctEntries := map[egressmapha.EgressCtKey4]egressmapha.EgressCtVal4{}
	manager.ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			ctEntries[*key] = *val
		})

	policyMatchesCtEntry := func(policy *PolicyConfig, ctKey *egressmapha.EgressCtKey4, ctVal *egressmapha.EgressCtVal4) bool {
		gatewayIP, ok := ip.AddrFromIP(ctVal.Gateway.IP())
		if !ok {
			log.Error("Cannot parse CT entry's gateway IP while removing expired entries")
			return false
		}

	nextDstCIDR:
		for _, dstCIDR := range policy.dstCIDRs {
			if !dstCIDR.Contains(ctKey.DestAddr.Addr()) {
				continue
			}

			for _, excludedCIDR := range policy.excludedCIDRs {
				if excludedCIDR.Contains(ctKey.DestAddr.Addr()) {
					continue nextDstCIDR
				}
			}

			// no need to check also endpointIP.Equal(endpointIP) as we are iterating
			// over the slice of policies returned by the
			// policyConfigsBySourceIP[ipRule.Src.IP.String()] map
			for _, healthyGatewayIP := range policy.gatewayConfig.healthyGatewayIPs {
				if healthyGatewayIP == gatewayIP {
					return true
				}
			}
		}

		return false
	}

nextCtKey:
	for ctKey, ctVal := range ctEntries {
		for _, policyConfig := range manager.policyConfigsBySourceIP[ctKey.SourceAddr.IP().String()] {
			if policyMatchesCtEntry(policyConfig, &ctKey, &ctVal) {
				continue nextCtKey
			}
		}

		logger := log.WithFields(logrus.Fields{
			// TODO log the whole ctKey
			logfields.SourceIP:  ctKey.SourceAddr.IP(),
			logfields.GatewayIP: ctVal.Gateway.IP(),
		})

		if err := manager.ctMap.Delete(&ctKey); err != nil {
			logger.WithError(err).Error("Error removing egress gateway CT entry")
		} else {
			logger.Debug("Egress gateway CT entry removed")
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

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()

	// clear the events bitmap
	manager.eventsBitmap = 0

	// Remove stale CT entries. We keep entries that point at an inactive Gateway node,
	// as long as the node is healthy.
	manager.removeExpiredCtEntries()

	manager.reconciliationEventsCount.Add(1)
}
