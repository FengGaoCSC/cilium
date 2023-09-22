// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	subsys    = "srv6"
	ownerName = "srv6-manager"
)

var (
	log                = logging.DefaultLogger.WithField(logfields.LogSubsys, subsys)
	legacySIDStructure = srv6Types.MustNewSIDStructure(128, 0, 0, 0)
)

// ErrSIDAlloc indicates an issue allocating a SID from the Manager's SID
// allocator.
//
// ErrSIDAlloc is capable of wrapping any errors exported by the implementation
// of a SID Allocator.
type ErrSIDAlloc struct {
	e error
}

func (e *ErrSIDAlloc) Error() string {
	return "failed to allocate SID: " + e.e.Error()
}

func (e *ErrSIDAlloc) Unwrap() error {
	return e.e
}

// BGPSignaler is an interface which exposes a method for notifying the BGP
// control plane of SRv6Manager state changes.
//
// The BGP control plane understands how to query the SRv6Mananger so no arguments
// are required.
type BGPSignaler interface {
	Event(_ interface{})
}

// SIDAllocation is a bookkeeping structure for locally allocated SIDs.
// These SID allocations serve as SRV6 VRF locators.
type SIDAllocation struct {
	VRFID             uint32
	ExportRouteTarget string
	SIDInfo           *sidmanager.SIDInfo
	LocatorPool       string
}

// The SRv6 manager stores the internal data to track SRv6 policies, VRFs,
// and SIDs. It also hooks up all the callbacks to update the BPF SRv6 maps
// accordingly.
//
// The SRv6 manager is capable of notifying the BGP Control Plane when changes
// to its internal databases occur.
type Manager struct {
	lock.RWMutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8s.CacheStatus

	// policies stores egress policies indexed by policyID
	policies map[policyID]*EgressPolicy

	// vrfs stores VRFs indexed by vrfID
	vrfs map[vrfID]*VRF

	// cepResource provides access to events and read-only store of CiliumEndpoint resources
	cepResource resource.Resource[*k8sTypes.CiliumEndpoint]

	// cepStore is a read-only store of CiliumEndpoint resources
	cepStore resource.Store[*k8sTypes.CiliumEndpoint]

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// allocatedSIDs map VRF IDs to their allocated SID if the VRF has an
	// ExportRouteTarget defined.
	//
	// When we encounter VRFs with a defined ExportRouteTarget field a SID is
	// allocated locally and stored in this map. The map is then referenced to
	// determine if SID allocation/deallocation is necessary on VRF reconciliation.
	allocatedSIDs map[uint32]*SIDAllocation

	// bgp is a handle to an instantiated BGPSignaler interface.
	// this interface informs the BGP control plane that the SRv6Manager's state
	// has changed.
	bgp BGPSignaler

	// sidAlloc is an IPv6Allocator used to allocate L3VPN service SID's on VRF
	// creation.
	sidAlloc ipam.Allocator

	// sidManager is an interface to interact with SIDManager
	sidManagerPromise promise.Promise[sidmanager.SIDManager]
	sidManager        sidmanager.SIDManager

	// A channel to trigger asynchronous reconcileVRF
	asyncReconcileVRFCh chan struct{}
}

type Params struct {
	cell.In

	Lifecycle              hive.Lifecycle
	DaemonConfig           *option.DaemonConfig
	Sig                    *signaler.BGPCPSignaler
	CacheIdentityAllocator cache.IdentityAllocator
	CacheStatus            k8s.CacheStatus
	SIDManagerPromise      promise.Promise[sidmanager.SIDManager]
	CiliumEndpointResource resource.Resource[*k8sTypes.CiliumEndpoint]
}

// NewSRv6Manager returns a new SRv6 policy manager.
func NewSRv6Manager(p Params) *Manager {
	if !p.DaemonConfig.EnableSRv6 {
		return nil
	}

	manager := &Manager{
		k8sCacheSyncedChecker: p.CacheStatus,
		policies:              make(map[policyID]*EgressPolicy),
		vrfs:                  make(map[vrfID]*VRF),
		identityAllocator:     p.CacheIdentityAllocator,
		allocatedSIDs:         make(map[uint32]*SIDAllocation),
		bgp:                   p.Sig,
		sidManagerPromise:     p.SIDManagerPromise,
		asyncReconcileVRFCh:   make(chan struct{}, 1),
		cepResource:           p.CiliumEndpointResource,
	}

	p.Lifecycle.Append(manager)

	return manager
}

// Notice that this Start hook is not only the place that does an
// initialization of SRv6Manager. Some initialization logics like k8s event
// handlers are still relying on the legacy Daemon-based initialization.
func (manager *Manager) Start(hookCtx hive.HookContext) error {
	// SIDManager's Start hook should already called and initial sync is
	// running. So, it's safe to wait on it.
	sidManager, err := manager.sidManagerPromise.Await(hookCtx)
	if err != nil {
		return fmt.Errorf("failed to await on SIDManager")
	}

	// Create Endpoints store and watch for Endpoints events
	manager.cepStore, err = manager.cepResource.Store(hookCtx)
	if err != nil {
		return fmt.Errorf("failed creating Endpoints resource.Store: %w", err)
	}
	go func() {
		epSynced := false
		for event := range manager.cepResource.Events(hookCtx) {
			// reconcile upon CiliumEndpoint events
			manager.Lock()
			switch event.Kind {
			case resource.Sync:
				epSynced = true
				manager.reconcileVRF()
			case resource.Upsert, resource.Delete:
				if epSynced {
					manager.reconcileVRF()
				}
			}
			manager.Unlock()
			event.Done(nil)
		}
	}()

	// This goroutine handles asynchronous reconcileVRF
	go func() {
		for range manager.asyncReconcileVRFCh {
			manager.Lock()
			log.Debug("Asynchronous reconcileVRF started")
			manager.reconcileVRF()
			log.Debug("Asynchronous reconcileVRF finished")
			manager.Unlock()
		}
	}()

	go func() {
		// Wait for an initial k8s resource sync. This is required for
		// VRF SID restoration after agent restart. When we subscribe
		// to the SID manager, it calls OnAddLocator for all existing
		// locators. Within the callback, SRv6Manager must retrieve an
		// existing SID allocation for all VRFs. Thus, at that point,
		// all VRFs must be synced.
		//
		// This needs to be asynchronous and we shouldn't block within
		// SRv6Manager's Start hook since the Daemon depends on
		// SRv6Manager to register it to k8s VRF event handler and it
		// is called after this Start hook.
		<-manager.k8sCacheSyncedChecker

		// Subscribe to the locator changes. At the same time, restore
		// all existing SID allocations. After this call, all VRFs that
		// allocate SIDs from locator pool should get SIDs.
		sidManager.Subscribe(ownerName, manager, func() {
			manager.Lock()
			defer manager.Unlock()

			// Now we can set sidManager since the initial sync is done.
			// This makes sidAllocatorIsSet to return true. From now on,
			// VRF k8s event handler can allocate SIDs from SIDManager.
			manager.sidManager = sidManager

			// SIDManager-related initialization is done. Kick an
			// initial VRF reconciliation. This needs to be async
			// because reconcileVRF may call ManageSID internally
			// and calling it within this callback is prohibited.
			manager.scheduleReconcileVRF()
		})
	}()

	return nil
}

func (manager *Manager) Stop(hookCtx hive.HookContext) error {
	return nil
}

func (manager *Manager) updateVRFSIDAllocation(vrf *VRF, pool string, newInfo *sidmanager.SIDInfo) {
	vrf.SIDInfo = newInfo
	manager.allocatedSIDs[vrf.VRFID] = &SIDAllocation{
		VRFID:             vrf.VRFID,
		ExportRouteTarget: vrf.ExportRouteTarget,
		SIDInfo:           newInfo,
		LocatorPool:       pool,
	}
}

func (manager *Manager) deleteVRFSIDAllocation(vrfID uint32) {
	delete(manager.allocatedSIDs, vrfID)
}

func (manager *Manager) restoreExistingAllocations(pool string, allocator sidmanager.SIDAllocator) {
	for _, info := range allocator.AllocatedSIDs(ownerName) {
		// Find VRF associated with this SID from allocation metadata
		if vrf, exists := manager.vrfs[types.NamespacedName{Name: info.MetaData}]; !exists {
			// SID is allocated, but associated VRF doesn't exist.
			// One possible case is users delete the VRF while
			// Cilium is stopping. Release the SID to align with an
			// actual state.
			if err := allocator.Release(info.SID.Addr); err != nil {
				log.WithError(err).Warn("Failed to release stale SID")
			} else {
				log.WithFields(logrus.Fields{
					logfields.VRF: info.MetaData,
					logfields.SID: info.SID.String(),
				}).Debug("Released stale SID")
			}
		} else {
			// This VRF doesn't need SID allocation anymore.
			// Release existing SID allocation. This happens
			// when users modify the ExportRouteTarget while
			// Cilium is stopping.
			if vrf.ExportRouteTarget == "" {
				if err := allocator.Release(info.SID.Addr); err != nil {
					log.WithError(err).Warn("Failed to release stale SID")
				} else {
					log.WithFields(logrus.Fields{
						logfields.VRF: info.MetaData,
						logfields.SID: info.SID.String(),
					}).Debug("Released stale SID")
				}
				continue
			}

			// This VRF is not interested in this pool anymore.
			// Release existing SID allocation. This happens when
			// users modifiy the LocatorPool while Cilium is
			// stopping.
			if vrf.LocatorPool != pool {
				if err := allocator.Release(info.SID.Addr); err != nil {
					log.WithError(err).Warn("Failed to release stale SID")
					continue
				} else {
					log.WithFields(logrus.Fields{
						logfields.VRF: info.MetaData,
						logfields.SID: info.SID.String(),
					}).Debug("Released stale SID")
				}
			} else {
				if vrf.SIDInfo != nil {
					// SID is already allocated for this
					// VRF. This happens when there's two
					// or more SID bounded to this VRF.
					// Currently, we suppose to have only
					// one SID for each VRF, so this is a
					// bug. The desired state here is
					// there's only one SID allocated for
					// each VRF, so release the SID which
					// we are seeing now.
					if err := allocator.Release(info.SID.Addr); err != nil {
						log.WithError(err).Warn("Failed to release stale SID")
						continue
					}

					log.WithFields(logrus.Fields{
						logfields.VRF: info.MetaData,
						logfields.SID: info.SID.String(),
					}).Warn("More than one SID allocation for the VRF observed. Releasing unnecessary allocation.")
				} else {
					// Restore SID
					vrf.SIDInfo = info

					manager.allocatedSIDs[vrf.VRFID] = &SIDAllocation{
						VRFID:             vrf.VRFID,
						ExportRouteTarget: vrf.ExportRouteTarget,
						SIDInfo:           info,
						LocatorPool:       pool,
					}

					log.WithFields(logrus.Fields{
						logfields.VRF: info.MetaData,
						logfields.SID: info.SID.String(),
					}).Debug("Restored SID allocation")
				}
			}
		}
	}
}

func (manager *Manager) OnAddLocator(pool string, allocator sidmanager.SIDAllocator) {
	manager.Lock()
	defer manager.Unlock()

	// Restore an existing allocation from pool. This is only called in the
	// context of an initial Subscribe() after agent restart.
	if manager.sidManager == nil {
		manager.restoreExistingAllocations(pool, allocator)
	}

	// Iterate over all existing VRFs and allocate SID if missing
	for id, vrf := range manager.vrfs {
		// This VRF is not interested in this pool
		if vrf.LocatorPool != pool {
			continue
		}

		// This VRF doesn't require SID allocation
		if vrf.ExportRouteTarget == "" {
			continue
		}

		// Allocation already exists
		if vrf.SIDInfo != nil {
			continue
		}

		info, err := allocator.AllocateNext(ownerName, id.Name, manager.selectBehavior(allocator.BehaviorType()))
		if err != nil {
			log.WithError(err).Error("Failed to allocate SID")
			continue
		}

		manager.updateVRFSIDAllocation(vrf, pool, info)
	}

	// We shouldn't call reconcileVRF synchronously here because it may
	// call ManageSID internally and calling ManageSID within subscription
	// handler is prohibited.
	manager.scheduleReconcileVRF()
}

func (manager *Manager) OnUpdateLocator(pool string, oldAllocator, newAllocator sidmanager.SIDAllocator) {
	manager.Lock()
	defer manager.Unlock()

	// Update all existing allocations associated with this pool
	for id, vrf := range manager.vrfs {
		if vrf.ExportRouteTarget == "" {
			continue
		}

		if vrf.LocatorPool != pool {
			continue
		}

		if vrf.SIDInfo == nil {
			continue
		}

		var (
			err  error
			info *sidmanager.SIDInfo
		)

		behavior := manager.selectBehavior(newAllocator.BehaviorType())

		// Try to allocate the same SID first to reduce BGP update churn
		info, err = newAllocator.Allocate(vrf.SIDInfo.SID.Addr, ownerName, id.Name, behavior)
		if err != nil {
			// Failed to allocate the same SID from new pool. This
			// is still ok. Allocate a brand new SID.
			info, err = newAllocator.AllocateNext(ownerName, id.Name, behavior)
			if err != nil {
				log.WithError(err).Error("Failed to allocate SID")
				continue
			}
		}

		manager.deleteVRFSIDAllocation(vrf.VRFID)
		manager.updateVRFSIDAllocation(vrf, pool, info)
	}

	manager.scheduleReconcileVRF()
}

func (manager *Manager) OnDeleteLocator(pool string, allocator sidmanager.SIDAllocator) {
	manager.Lock()
	defer manager.Unlock()

	// Delete all existing allocations associated with this pool
	for _, vrf := range manager.vrfs {
		if vrf.ExportRouteTarget == "" {
			continue
		}

		if vrf.LocatorPool != pool {
			continue
		}

		if vrf.SIDInfo == nil {
			continue
		}

		if err := allocator.Release(vrf.SIDInfo.SID.Addr); err != nil {
			log.WithError(err).Error("Failed to release SID allocated from deleted pool")
		}

		vrf.SIDInfo = nil
		manager.deleteVRFSIDAllocation(vrf.VRFID)
	}

	manager.scheduleReconcileVRF()
}

func (manager *Manager) SetSIDAllocator(a ipam.Allocator) {
	manager.Lock()
	defer manager.Unlock()
	manager.sidAlloc = a
}

func (manager *Manager) sidAllocatorIsSet() bool {
	return manager.sidAlloc != nil && manager.sidManager != nil
}

// GetAllVRFs returns a slice with all copy of VRFs known to the SRv6 manager.
func (manager *Manager) GetAllVRFs() []*VRF {
	manager.RLock()
	defer manager.RUnlock()

	vrfs := make([]*VRF, 0, len(manager.vrfs))
	for _, vrf := range manager.vrfs {
		vrfs = append(vrfs, vrf.DeepCopy())
	}
	return vrfs
}

// GetVRFs returns a slice with copy of VRFs known to the SRv6 manager that
// have the given import route-target.
func (manager *Manager) GetVRFs(importRouteTarget string) []*VRF {
	manager.RLock()
	defer manager.RUnlock()

	vrfs := make([]*VRF, 0, len(manager.vrfs))
	for _, vrf := range manager.vrfs {
		if vrf.ImportRouteTarget == importRouteTarget {
			vrfs = append(vrfs, vrf.DeepCopy())
		}
	}
	return vrfs
}

// GetEgressPolicies returns a slice with the SRv6 egress policies known to the
// SRv6 manager.
func (manager *Manager) GetEgressPolicies() []*EgressPolicy {
	manager.RLock()
	defer manager.RUnlock()

	policies := make([]*EgressPolicy, 0, len(manager.policies))
	for _, policy := range manager.policies {
		policies = append(policies, policy.DeepCopy())
	}
	return policies
}

// Event handlers

// OnAddSRv6Policy and updates the manager internal state with the policy
// fields.
func (manager *Manager) OnAddSRv6Policy(policy EgressPolicy) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumSRv6EgressPolicyName, policy.id.Name)

	if _, ok := manager.policies[policy.id]; !ok {
		logger.Info("Added CiliumSRv6EgressPolicy")
	} else {
		logger.Info("Updated CiliumSRv6EgressPolicy")
	}

	manager.policies[policy.id] = &policy

	manager.reconcilePoliciesAndSIDs()
}

// OnDeleteSRv6Policy deletes the internal state associated with the given
// policy.
func (manager *Manager) OnDeleteSRv6Policy(policyID policyID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumSRv6EgressPolicyName, policyID.Name)

	if manager.policies[policyID] == nil {
		logger.Warn("Can't delete CiliumSRv6EgressPolicy: policy not found")
		return
	}

	logger.Info("Deleted CiliumSRv6EgressPolicy")

	delete(manager.policies, policyID)

	manager.reconcilePoliciesAndSIDs()
}

// OnAddSRv6VRF and updates the manager internal state with the VRF
// config fields.
func (manager *Manager) OnAddSRv6VRF(vrf VRF) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumSRv6VRFName, vrf.id.Name)

	if _, ok := manager.vrfs[vrf.id]; !ok {
		logger.Info("Added CiliumSRv6VRF")
	} else {
		logger.Info("Updated CiliumSRv6VRF")
	}

	manager.vrfs[vrf.id] = &vrf

	manager.reconcileVRF()
}

// OnDeleteSRv6VRF deletes the internal state associated with the given VRF.
func (manager *Manager) OnDeleteSRv6VRF(vrfID vrfID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumSRv6VRFName, vrfID.Name)

	if manager.vrfs[vrfID] == nil {
		logger.Warn("Can't delete CiliumSRv6VRF: policy not found")
		return
	}

	logger.Info("Deleted CiliumSRv6VRF")

	delete(manager.vrfs, vrfID)

	manager.reconcileVRF()
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

// addMissingSRv6PolicyRules is responsible for adding any missing egress SRv6
// policies stored in the manager (i.e. k8s CiliumSRv6EgressPolicies) to the
// egress policy BPF map.
func (manager *Manager) addMissingSRv6PolicyRules() {
	srv6Policies := map[srv6map.PolicyKey]srv6map.PolicyValue{}
	srv6map.SRv6PolicyMap4.IterateWithCallback4(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})
	srv6map.SRv6PolicyMap6.IterateWithCallback6(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})

	var err error
	for _, policy := range manager.policies {
		for _, dstCIDR := range policy.DstCIDRs {
			policyKey := srv6map.PolicyKey{
				VRFID:    policy.VRFID,
				DestCIDR: dstCIDR,
			}

			policyVal, policyPresent := srv6Policies[policyKey]
			if policyPresent && policyVal.SID == policy.SID {
				continue
			}

			err = srv6map.GetPolicyMap(policyKey).Update(policyKey, policy.SID)

			logger := log.WithFields(logrus.Fields{
				logfields.VRF:             policy.VRFID,
				logfields.DestinationCIDR: *dstCIDR,
				logfields.SID:             policy.SID,
			})
			if err != nil {
				logger.WithError(err).Error("Error applying egress SRv6 policy")
			} else {
				logger.Info("Egress SRv6 policy applied")
			}
		}
	}
}

// removeUnusedSRv6PolicyRules is responsible for removing any entry in the SRv6 policy BPF map which
// is not baked by an actual k8s CiliumSRv6EgressPolicy.
//
// The algorithm for this function can be expressed as:
//
//	nextPolicyKey:
//	for each entry in the srv6_policy map {
//	    for each policy in k8s CiliumSRv6EgressPolices {
//	        if policy matches entry {
//	            // we found one k8s policy that matches the current BPF entry, move to the next one
//	            continue nextPolicyKey
//	        }
//	    }
//
//	    // the current BPF entry is not backed by any k8s policy, delete it
//	    srv6map.RemoveSRv6Policy(entry)
//	}
func (manager *Manager) removeUnusedSRv6PolicyRules() {
	srv6Policies := map[srv6map.PolicyKey]srv6map.PolicyValue{}
	srv6map.SRv6PolicyMap4.IterateWithCallback4(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})
	srv6map.SRv6PolicyMap6.IterateWithCallback6(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})

nextPolicyKey:
	for policyKey := range srv6Policies {
		for _, policy := range manager.policies {
			for _, dstCIDR := range policy.DstCIDRs {
				if policyKey.Match(policy.VRFID, dstCIDR) {
					continue nextPolicyKey
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.VRF:             policyKey.VRFID,
			logfields.DestinationCIDR: policyKey.DestCIDR,
		})

		if err := srv6map.GetPolicyMap(policyKey).Delete(policyKey); err != nil {
			logger.WithError(err).Error("Error removing SRv6 egress policy")
		} else {
			logger.Info("SRv6 egress policy removed")
		}
	}
}

func (manager *Manager) addMissingSRv6SIDs() {
	for _, vrf := range manager.vrfs {
		if vrf.SIDInfo == nil {
			continue
		}
		if err := manager.updateSIDMap(vrf.SIDInfo.SID, vrf.VRFID); err != nil {
			log.WithField("VRF", vrf.id.Name).WithError(err).Error("VRF has SID allocation and SIDMap entry is missing, but failed to update")
			continue
		}
	}
}

// removeUnusedSRv6SIDs implements the same as removeUnusedSRv6PolicyRules but
// for the SID map.
func (manager *Manager) removeUnusedSRv6SIDs() {
	srv6SIDs := map[srv6map.SIDKey]srv6map.SIDValue{}
	srv6map.SRv6SIDMap.IterateWithCallback(
		func(key *srv6map.SIDKey, val *srv6map.SIDValue) {
			srv6SIDs[*key] = *val
		})

nextSIDKey:
	for sidKey := range srv6SIDs {
		for _, allocation := range manager.allocatedSIDs {
			if sidKey.SID.Addr() == allocation.SIDInfo.SID.Addr {
				continue nextSIDKey
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SID: sidKey.SID,
		})

		if err := srv6map.SRv6SIDMap.Delete(sidKey); err != nil {
			logger.WithError(err).Error("Error removing SID")
		} else {
			logger.Info("SID removed")
		}
	}
}

// reconcileVRFEgressPath will add and remove mappings from the SRv6VRF
// maps given the current Manager's VRF database.
//
// A VRF is expanded into one or more VRFKey structures which act as keys and
// map to the VRF's ID if the VRF's endpoint selector matches an endpoint's
// label.
//
// The manager keeps a database of known endpoints to compare VRF selection against.
func (m *Manager) reconcileVRFEgressPath() {
	type keyEntry struct {
		key   *srv6map.VRFKey
		value *srv6map.VRFValue
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "srv6.Manager.reconcileVRFEgressPath",
			},
		)
		srv6VRFs = map[string]keyEntry{}
	)

	log.Info("Reconciling egress datapath for encapsulation.")

	// populate srv6VRFs map
	srv6map.SRv6VRFMap4.IterateWithCallback4(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[key.String()] = keyEntry{
				key:   key,
				value: val,
			}
		})
	srv6map.SRv6VRFMap6.IterateWithCallback6(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[key.String()] = keyEntry{
				key:   key,
				value: val,
			}
		})

	for _, vrf := range m.vrfs {
		keys := m.getVRFKeysFromMatchingEndpoint(vrf)
		for _, key := range keys {
			vrfVal, vrfPresent := srv6VRFs[key.String()]
			if vrfPresent && vrfVal.value.ID == vrf.VRFID {
				continue
			}
			logger := l.WithFields(logrus.Fields{
				logfields.SourceIP:        key.SourceIP,
				logfields.DestinationCIDR: key.DestCIDR,
				logfields.VRF:             vrf.VRFID,
			})
			if err := srv6map.GetVRFMap(key).Update(key, vrf.VRFID); err != nil {
				logger.WithError(err).Error("Error applying SRv6 VRF mapping")
			} else {
				logger.Info("SRv6 VRF mapping applied")
			}
		}
	}

	// remove any existing VRF entries
nextVRFKey:
	for _, vrfKeyEntry := range srv6VRFs {
		for _, vrf := range m.vrfs {
			keys := m.getVRFKeysFromMatchingEndpoint(vrf)
			for _, key := range keys {
				if vrfKeyEntry.key.Match(*key.SourceIP, key.DestCIDR) {
					continue nextVRFKey
				}
			}
		}
		logger := l.WithFields(logrus.Fields{
			logfields.SourceIP:        vrfKeyEntry.key.SourceIP,
			logfields.DestinationCIDR: vrfKeyEntry.key.DestCIDR,
		})

		if err := srv6map.GetVRFMap(*vrfKeyEntry.key).Delete(*vrfKeyEntry.key); err != nil {
			logger.WithError(err).Error("Error removing SRv6 VRF mapping")
		} else {
			logger.Info("SRv6 VRF mapping removed")
		}
	}
}

// When a VRF has a defined "ExportRouteTarget" we must configure both the Manager
// and the eBPF datapath to process ingress traffic destined to the VRF being
// exported.
//
// This function will organize the Manager's VRFs and SID allocations and then
// create or remove both according to the Manager's state.
func (m *Manager) reconcileVRFIngressPath() {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "srv6.Manager.reconcileVRFIngressPath",
			},
		)
		toCreate = []*VRF{}
		toUpdate = []*VRF{}
		toRemove = []*SIDAllocation{}
	)

	// By the time we are in this method, the VRF event has been indexed into
	// the manager's VRF field.
	//
	// ATTENTION: A subtlety exists here in that VRF updates from Kubernetes know nothing
	// about locally allocated SIDs and an update event can overwrite the a VRF's
	// locally allocated SID. Therefore, this method must also repopulate the
	// SID's Allocated VRF field.
	for _, v := range m.vrfs {
		alloc, hasSID := m.allocatedSIDs[v.VRFID]

		// does this vrf have an ExportRouteTarget and no SID allocation?
		if v.ExportRouteTarget != "" && !hasSID {
			toCreate = append(toCreate, v)
			continue
		}

		// does this VRF have an existing SID allocation?
		if hasSID {
			// ExportRouteTarget undefined, remove this allocation.
			if v.ExportRouteTarget == "" {
				toRemove = append(toRemove, alloc)
				continue
			}

			// SID allocation exists, does ExportRouteTarget match it?
			if v.ExportRouteTarget != alloc.ExportRouteTarget {
				// NOTE: it is possible the ExportRouteTarget may have been changed
				// by the user.
				// in this case, we will update the SID allocation, and the BGP
				// control plane with re-advertise the SID with the updated
				// ExportRouteTarget on it's next reconciliation loop.
				alloc.ExportRouteTarget = v.ExportRouteTarget
			}

			// SID allocation exists and ExportRouteTarget is the same, re-write
			// allocated SID incase an update overwritten it. See: ATTENTION:
			v.SIDInfo = alloc.SIDInfo

			// Locator pool changed. Need SID reallocation.
			if v.LocatorPool != alloc.LocatorPool {
				toUpdate = append(toUpdate, v)
			}
		}
	}
	// if we have any allocated SIDs which do not have associated VRF definitions
	// remove them.
	for vrfID := range m.allocatedSIDs {
		found := false
		for _, vrf := range m.vrfs {
			if vrf.VRFID == vrfID {
				found = true
				break
			}
		}
		if !found {
			toRemove = append(toRemove, m.allocatedSIDs[vrfID])
		}
	}
	l.WithFields(logrus.Fields{
		"toCreate": len(toCreate),
		"toUpdate": len(toUpdate),
		"toRemove": len(toRemove),
	}).Debug("Reconciling ingress VRF mappings for decapsulation.")

	// remove any SIDs in the SID map which we do not have allocations for
	m.removeUnusedSRv6SIDs()

	// add any SIDs which have allocation, but SIDMap entry is missing
	m.addMissingSRv6SIDs()

	m.createIngressPathVRFs(toCreate)
	m.updateIngressPathVRFs(toUpdate)
	m.removeIngressPathVRFs(toRemove)
}

func (m *Manager) selectBehavior(behaviorType srv6Types.BehaviorType) srv6Types.Behavior {
	switch behaviorType {
	case srv6Types.BehaviorTypeBase:
		return srv6Types.BehaviorEndDT4
	case srv6Types.BehaviorTypeUSID:
		return srv6Types.BehaviorUDT4
	default:
		return srv6Types.BehaviorUnknown
	}
}

// allocateSID allocates SID from SIDAllocator. It hides an implementation
// difference between two allocation method we support right now. When the pool
// is an empty string, it allocates SID from legacy IPAM-based allocator and
// otherwise, it allocates SID from SIDManager.
func (m *Manager) allocateSID(pool, metadata string) (*sidmanager.SIDInfo, error) {
	if pool == "" {
		res, err := m.sidAlloc.AllocateNext(ownerName, "")
		if err != nil {
			return nil, err
		}

		addr, ok := ip.AddrFromIP(res.IP)
		if !ok {
			err := fmt.Errorf("failed to convert IP to Addr")
			if releaseErr := m.sidAlloc.Release(res.IP, ""); releaseErr != nil {
				err = errors.Join(err, fmt.Errorf("failed to release SID: %w", releaseErr))
			}
			return nil, err
		}

		sid, err := srv6Types.NewSID(addr, legacySIDStructure)
		if err != nil {
			m.sidAlloc.Release(res.IP, "")
			return nil, fmt.Errorf("failed to create SID: %w", err)
		}

		info := &sidmanager.SIDInfo{
			Owner:    ownerName,
			MetaData: metadata,
			SID:      sid,
			Behavior: srv6Types.BehaviorEndDT4,
		}

		return info, nil
	} else {
		var info *sidmanager.SIDInfo

		if err := m.sidManager.ManageSID(pool, func(allocator sidmanager.SIDAllocator) (bool, error) {
			var err error

			behavior := m.selectBehavior(allocator.BehaviorType())
			if behavior == srv6Types.BehaviorUnknown {
				return false, fmt.Errorf("unknown behavior")
			}

			info, err = allocator.AllocateNext(ownerName, metadata, behavior)
			if err != nil {
				return false, err
			}

			return true, nil
		}); err != nil {
			return nil, err
		}

		return info, nil
	}
}

// releaseSID releases SID from SIDAllocator. It hides an implementation
// difference between two allocation method we support right now. When the pool
// is an empty string, it releases SID with legacy IPAM-based allocator and
// otherwise, it releases SID with SIDManager.
func (m *Manager) releaseSID(pool string, sid *srv6Types.SID) error {
	if pool == "" {
		if err := m.sidAlloc.Release(net.IP(sid.Addr.AsSlice()), ""); err != nil {
			return err
		}
		return nil
	} else {
		if err := m.sidManager.ManageSID(pool, func(allocator sidmanager.SIDAllocator) (bool, error) {
			if err := allocator.Release(sid.Addr); err != nil {
				return false, err
			}
			return true, nil
		}); err != nil {
			return err
		}
		return nil
	}
}

func (m *Manager) updateSIDMap(sid *srv6Types.SID, vrfID uint32) error {
	k, err := srv6map.NewSIDKeyFromSID(sid)
	if err != nil {
		return err
	}
	return srv6map.SRv6SIDMap.Update(*k, vrfID)
}

func (m *Manager) deleteSIDMap(sid *srv6Types.SID) error {
	k, err := srv6map.NewSIDKeyFromSID(sid)
	if err != nil {
		return err
	}
	return srv6map.SRv6SIDMap.Delete(*k)
}

// createIngressPathVRFs will range over the provided VRFs and configure
// the datapath for ingressing VPN traffic destined for this node's VRF.
//
// The ingress path configuration consists of the following for newly exported VRFs.
// 1. Allocating a SID for the VRF if necessary
// 2. Writing this SID and its associated VRF ID to the SRv6SIDMap //TODO: checking spelling
// 3. Store the allocated SID wihin the Manager's memory.
func (m *Manager) createIngressPathVRFs(vrfs []*VRF) {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.createIngressPathVRFs",
		},
	)
	for _, vrf := range vrfs {
		func(vrf *VRF) {
			// ATTENTION: variables declared here so cleanup function can close
			// over them, do not redeclare these vars.
			var (
				err  error
				info *sidmanager.SIDInfo
			)

			// allocate a SID and defer possible cleanup.
			info, err = m.allocateSID(vrf.LocatorPool, vrf.id.Name)
			if err != nil {
				l.WithField("vrf", vrf.id.Name).WithError(err).Error("Failed to allocate SID for VRF")
				return
			}
			defer func() {
				if err != nil {
					if err := m.releaseSID(vrf.LocatorPool, info.SID); err != nil {
						l.WithError(err).Errorf("Failed to cleanup SID Allocation %s", info.SID.String())
					}
				}
			}()

			// populate SID map
			err = m.updateSIDMap(info.SID, vrf.VRFID)
			if err != nil {
				l.WithField("vrf", vrf.id.Name).WithError(err).Error("Failed to update SID Map")
				return
			}

			m.updateVRFSIDAllocation(vrf, vrf.LocatorPool, info)

			l.WithFields(logrus.Fields{
				"VRF":               vrf.id.Name,
				"LocatorPool":       vrf.LocatorPool,
				"SID":               vrf.SIDInfo.SID.String(),
				"ExportRouteTarget": vrf.ExportRouteTarget,
			}).Info("Allocated SID for VRF with export route target.")
		}(vrf)
	}
}

func (m *Manager) updateIngressPathVRFs(vrfs []*VRF) {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.updateIngressPaths",
		},
	)
	for _, vrf := range vrfs {
		func() {
			var (
				err     error
				newInfo *sidmanager.SIDInfo
			)

			l := l.WithField("vrf", vrf.id.Name)

			oldAllocation, ok := m.allocatedSIDs[vrf.VRFID]
			if !ok {
				l.Error("Failed to retrieve old SID")
				return
			}

			newInfo, err = m.allocateSID(vrf.LocatorPool, vrf.id.Name)
			if err != nil {
				l.WithError(err).Error("Failed to allocate new SID")
				return
			}

			defer func() {
				if err != nil {
					if err := m.releaseSID(vrf.LocatorPool, newInfo.SID); err != nil {
						l.WithError(err).Error("Failed to recover by releasing new SID")
					}
				}
			}()

			err = m.deleteSIDMap(oldAllocation.SIDInfo.SID)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				l.WithError(err).Error("Failed to delete SID map entry")
				return
			}

			defer func() {
				if err != nil {
					if err := m.updateSIDMap(oldAllocation.SIDInfo.SID, vrf.VRFID); err != nil {
						l.WithError(err).Error("Failed to recover by updating SID Map with old SID")
					}
				}
			}()

			err = m.releaseSID(oldAllocation.LocatorPool, oldAllocation.SIDInfo.SID)
			if err != nil {
				l.WithError(err).Error("failed to release old SID")
				return
			}

			err = m.updateSIDMap(newInfo.SID, vrf.VRFID)
			if err != nil {
				l.WithError(err).Error("Failed to update SID map entry")
				return
			}

			defer func() {
				if err != nil {
					if err := m.deleteSIDMap(newInfo.SID); err != nil {
						l.WithError(err).Error("Failed to recover by deleting new SID from SID Map")
					}
				}
			}()

			m.deleteVRFSIDAllocation(oldAllocation.VRFID)
			m.updateVRFSIDAllocation(vrf, vrf.LocatorPool, newInfo)

			l.WithFields(logrus.Fields{
				"VRF":               vrf.id.Name,
				"LocatorPool":       vrf.LocatorPool,
				"SID":               vrf.SIDInfo.SID.String(),
				"ExportRouteTarget": vrf.ExportRouteTarget,
			}).Info("Updated SID for VRF")
		}()
	}
}

// removeIngressPathVRFs ranges over the provided SIDAllocation(s) and
// removes their existence from the data path.
//
// this is essentially the opposite of createIngressPathVRF.
//
// if an error occurs in any of the operations involved with removing a SID
// allocation the removal will be tried again on next reconciliation.
func (m *Manager) removeIngressPathVRFs(allocs []*SIDAllocation) {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.removeIngressPaths",
		},
	)
	for _, alloc := range allocs {
		l := l.WithFields(
			logrus.Fields{
				"SID":               alloc.SIDInfo.SID.String(),
				"exportRouteTarget": alloc.ExportRouteTarget,
				"vrfID":             alloc.VRFID,
			},
		)
		var shouldRelease = true
		if err := m.deleteSIDMap(alloc.SIDInfo.SID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			l.WithError(err).Error("failed deleting SIDMap entry for allocation")
			shouldRelease = false
		}
		if shouldRelease {
			m.releaseSID(alloc.LocatorPool, alloc.SIDInfo.SID)
			m.deleteVRFSIDAllocation(alloc.VRFID)
			l.Info("Deleted SID allocation for VRF")
		}
	}
}

// reconcilePoliciesAndSIDs is responsible for reconciling the state of the
// manager (i.e. the desired state) with the actual state of the node (SRv6
// policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcilePoliciesAndSIDs() {
	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingSRv6PolicyRules()
	manager.removeUnusedSRv6PolicyRules()
}

// reconcileVRF is responsible for reconciling the state of the
// manager (i.e. the desired state) with the actual state of the node (SRv6
// VRF mapping maps).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileVRF() {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.reconcileVRF",
		},
	)

	if manager.sidAllocatorIsSet() {
		manager.reconcileVRFIngressPath()
	} else {
		l.Debug("SRv6 Manager not configured with SID Allocator yet, won't export VRFs.")
	}

	if srv6map.VRFMapsInitialized() {
		manager.reconcileVRFEgressPath()
	} else {
		l.Debug("SRv6 VRF maps not initialized yet, skipping egress datapath reconciliation.")
	}

	manager.bgp.Event(struct{}{})
}

// scheduleReconcileVRF schedules asynchronous reconcileVRF
func (manager *Manager) scheduleReconcileVRF() {
	select {
	case manager.asyncReconcileVRFCh <- struct{}{}:
		log.Debug("Scheduled VRF reconciliation")
	default:
		log.Debug("VRF reconciliation is already scheduled. Skipping.")
	}
}
