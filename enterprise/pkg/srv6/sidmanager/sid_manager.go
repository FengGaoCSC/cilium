//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sidmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sTypes "k8s.io/apimachinery/pkg/types"
)

// SID Manager is a central point of managing SRv6 SIDs. It is backed by
// per-node k8s resource that provides locators for the node as a spec and
// holds SID allocation state as a status. The locators will be allocated from
// the high-level "pool" of locators and usually, the Cilium Operator is
// responsible for allocating locators for each nodes.
//
// Internally, it manages SIDAllocator per-locator (can be a pool of locator
// prefixes) and other SRv6-related subsystems can manage SIDs with the name of
// the pool that the locator is allocated from. When the allocation state is
// changed, SID Manager takes care of reflecting the state to the k8s resource.

var (
	SRv6SIDManagerSubsys = "srv6-sid-manager"

	smLog = logging.DefaultLogger.WithField(logfields.LogSubsys, SRv6SIDManagerSubsys)
)

// SIDManager is an interface to interact with SID Manager subsystem
type SIDManager interface {
	// ManageSID executes fn with SIDAllocator corresponds to the given
	// poolName. The fn must return true when it modified the allocation
	// state (e.g. called Allocate, AllocateNext, or Release), so that the
	// modification made for the allocator will eventually synchronized to
	// the k8s resource state.
	ManageSID(poolName string, fn func(allocator SIDAllocator) (bool, error)) error

	// Subscribe registers callbacks to the add/update/delete of locator
	// pool with given poolName. When it registers for the first time, it
	// iterates over all available pools and calls OnAddLocator callback.
	// The modifications made for the allocator within the callbacks are
	// eventually synchronized to the k8s resource state.
	Subscribe(subscriberName string, subscriber SIDManagerSubscriber)
}

type SIDManagerSubscriber interface {
	// OnAddLocator is called when a new locator pool is added or when the
	// subscription starts. The callback function can allocate a new SID or
	// restore states from existing allocations (after the agent restart, a
	// new allocator may contain the SIDs allocated in the previous run).
	// This callback shouldn't block for a long time because it is executed
	// synchronously within the SID Manager's event loop. This function
	// should't call ManageSID inside it. Otherwise, it causes deadlock.
	OnAddLocator(poolName string, allocator SIDAllocator)

	// OnUpdateLocator is called when the definition of the locator pool is
	// changed (e.g. locator change or SID structure change). The callback
	// function must release all SIDs allocated from oldAllocator and
	// allocate new SIDs from newAllocator if needed. Any state associated
	// with SIDs allocated from the old allocator must be updated to the
	// new one associated with the SID allocated from the new allocator.
	// This callback shouldn't block for a long time because it is executed
	// synchronously within the SID Manager's event loop. This function
	// should't call ManageSID inside it. Otherwise, it causes deadlock.
	OnUpdateLocator(poolName string, oldAllocator SIDAllocator, newAllocator SIDAllocator)

	// OnDeleteLocator is called when a pool is deleted. The callback
	// function must release all SIDs and associated states from deleted
	// allocator. This callback shouldn't block for a long time because it
	// is executed synchronously within the SID Manager's event loop. This
	// function should't call ManageSID inside it. Otherwise, it causes
	// deadlock.
	OnDeleteLocator(poolName string, allocator SIDAllocator)
}

type sidManager struct {
	// PoolName => SIDAllocator mapping. We currently assume only one
	// locator allocated from one pool.
	allocators map[string]SIDAllocator

	// Lock to protect allocators
	allocatorsLock lock.RWMutex

	// Resource[T] of backing k8s resource
	resource LocalIsovalentSRv6SIDManagerResource

	// Clientset is a k8s clientset
	clientset client.Clientset

	// Channel that schedules k8s state synchronization. There's only 1
	// buffer and the write should be non-blocking.
	stateSyncCh chan struct{}

	// Resolver for the Promise for waiting an initial sync
	resolver promise.Resolver[SIDManager]

	// Subscriber name => Subscriber callbacks mapping
	subscribers map[string]SIDManagerSubscriber

	// Lock to protect subscribers
	subscribersLock lock.RWMutex

	// WaitGroup to wait for all goroutine's termination
	wg sync.WaitGroup

	// Function to cancel context shared with all goroutines
	cancel context.CancelFunc
}

type sidManagerParams struct {
	cell.In

	Lc       hive.Lifecycle
	Cs       client.Clientset
	Resource LocalIsovalentSRv6SIDManagerResource
}

// NewSIDManagerPromise creates a new SID manager and returns its promise. The
// promise will be resolved once the backing SIDManager resource is fetched and
// all initial allocator creation is done.
func NewSIDManagerPromise(params sidManagerParams) promise.Promise[SIDManager] {
	resolver, promise := promise.New[SIDManager]()

	m := &sidManager{
		allocators:  make(map[string]SIDAllocator),
		resource:    params.Resource,
		clientset:   params.Cs,
		stateSyncCh: make(chan struct{}, 1),
		resolver:    resolver,
		subscribers: make(map[string]SIDManagerSubscriber),
	}

	params.Lc.Append(m)

	return promise
}

func (m *sidManager) ManageSID(poolName string, fn func(allocator SIDAllocator) (bool, error)) error {
	m.allocatorsLock.RLock()
	defer m.allocatorsLock.RUnlock()

	allocator, ok := m.allocators[poolName]
	if !ok {
		return fmt.Errorf("allocator with pool %s doesn't exist", poolName)
	}

	needsSync, err := fn(allocator)
	if err != nil {
		return fmt.Errorf("management operation failed: %w", err)
	}

	if needsSync {
		m.scheduleStateSync()
	}

	return nil
}

func (m *sidManager) Subscribe(subscriberName string, subscriber SIDManagerSubscriber) {
	m.subscribersLock.Lock()
	if _, ok := m.subscribers[subscriberName]; ok {
		// Already subscribed
		m.subscribersLock.Unlock()
		return
	}
	m.subscribers[subscriberName] = subscriber
	m.subscribersLock.Unlock()

	// Do initial sync in-place
	m.allocatorsLock.RLock()

	for poolName, allocator := range m.allocators {
		subscriber.OnAddLocator(poolName, allocator)
	}

	if len(m.allocators) != 0 {
		// Subscriber may change allocation state in above OnAddLocator
		m.scheduleStateSync()
	}

	m.allocatorsLock.RUnlock()
}

func (m *sidManager) Start(hookCtx hive.HookContext) error {
	smLog.Info("Starting SRv6 SID Manager")

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	m.wg.Add(2)

	// This goroutine is responsible for watching SIDManager resource on
	// k8s and create SIDAllocator per locator allocations.
	go m.runSpecReconciler(ctx)

	// This goroutine is responsible for synchronizing a SID allocation
	// state to k8s resource.
	go m.runStatusReconciler(ctx)

	return nil
}

func (m *sidManager) Stop(hookCtx hive.HookContext) error {
	smLog.Info("Stopping SRv6 SID Manager")

	// This should make all goroutines cancel and yield
	m.cancel()

	// Wait for all goroutines to terminate
	ch := make(chan struct{})
	go func() {
		m.wg.Wait()
		ch <- struct{}{}
	}()

	select {
	case <-hookCtx.Done():
		return fmt.Errorf("stop timeout expired while waiting for goroutines to terminate")
	case <-ch:
		// All goroutines terminated. Go to the next stage.
		smLog.Info("All goroutines are shutdown")
	}

	// If there's an outstanding sync, try its best to do sync before shutdown
	select {
	case <-m.stateSyncCh:
		smLog.Info("Performing the last state sync before shutdown")
		_ = m.reconcileStatus(hookCtx)
	default:
	}

	return nil
}

func (m *sidManager) runSpecReconciler(ctx context.Context) {
	smLog.Info("Starting SID Manager spec reconciler")

	defer m.wg.Done()

	restorationDone := false
	for ev := range m.resource.Events(ctx) {
		switch ev.Kind {
		case resource.Sync:
			// At this point, we're ready for accepting ManageSID
			// or Subscribe call.
			m.resolver.Resolve(m)
			restorationDone = true
		case resource.Delete:
			smLog.Info("IsovalentSRv6SIDManager resource deleted")
			// Resource deleted. This shouldn't happen in practice
			// because SIDManager resource is per-node and its
			// lifecycle is aligned with the one of Node and most
			// of the time, the agent's lifecycle is aligned with
			// the node as well. So, this handler shouldn't be
			// called. The possible cases are the buggy operator or
			// the user manually deletes the resource.
			m.deleteAllAllocators(ev.Object)
		case resource.Upsert:
			// This reconciliation creates SID allocators from the
			// locator allocations on the spec. After this
			// function, state of the m.allocators is fully synced
			// with the spec on the k8s resource.
			needsSync, err := m.reconcileSpec(ev.Object)
			if err != nil {
				ev.Done(err)
				continue
			}

			if !restorationDone {
				// On the initial upsert after agent restart, we may
				// have existing allocations on k8s resource status.
				// Before schedule the initial state sync, try to
				// allocate existing SIDs from SID allocators, so that
				// we can retain same SIDs over agent restart.
				m.restoreAllocations(ctx, ev.Object)
				restorationDone = true
				needsSync = true
			}

			if needsSync {
				m.scheduleStateSync()
			}
		}
		ev.Done(nil)
	}

	smLog.Info("Stopping SID Manager spec reconciler")
}

// This function synchronizes internal poolName => allocator mappings to spec on the k8s resource
func (m *sidManager) reconcileSpec(r *v1alpha1.IsovalentSRv6SIDManager) (bool, error) {
	var needsSync bool

	m.subscribersLock.RLock()
	defer m.subscribersLock.RUnlock()

	m.allocatorsLock.Lock()
	defer m.allocatorsLock.Unlock()

	pools := make(map[string]struct{})
	for _, la := range r.Spec.LocatorAllocations {
		// Keep the name of the pools on the spec on the map so that we
		// can search the name in O(1) in the later deletion handling.
		pools[la.PoolRef] = struct{}{}

		if len(la.Locators) != 1 {
			return false, fmt.Errorf("multiple locator from same pool is not supported yet")
		}

		locator := la.Locators[0]

		l, err := m.locatorFromResource(locator)
		if err != nil {
			return false, fmt.Errorf("failed to create locator: %w", err)
		}

		behaviorType := types.BehaviorTypeFromString(locator.BehaviorType)

		if oldAllocator, ok := m.allocators[la.PoolRef]; !ok {
			newAllocator, err := NewStructuredSIDAllocator(l, behaviorType)
			if err != nil {
				return false, fmt.Errorf("failed to create new SID allocator: %w", err)
			}
			m.onAddLocator(la.PoolRef, newAllocator)
			needsSync = true
		} else {
			// No change to the spec, skip update
			if *oldAllocator.Locator() == *l && oldAllocator.BehaviorType() == behaviorType {
				continue
			}
			newAllocator, err := NewStructuredSIDAllocator(l, behaviorType)
			if err != nil {
				return false, fmt.Errorf("failed to create new SID allocator: %w", err)
			}
			m.onUpdateLocator(la.PoolRef, oldAllocator, newAllocator)
			needsSync = true
		}
	}

	for _, poolRef := range maps.Keys(m.allocators) {
		if _, ok := pools[poolRef]; ok {
			continue
		}
		m.onDeleteLocator(poolRef, m.allocators[poolRef])
		needsSync = true
	}

	return needsSync, nil
}

// Handle locator add. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onAddLocator(poolRef string, newAllocator SIDAllocator) {
	if len(m.subscribers) > 0 {
		for _, subscriber := range m.subscribers {
			subscriber.OnAddLocator(poolRef, newAllocator)
		}
	}
	m.allocators[poolRef] = newAllocator
}

// Handle locator update. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onUpdateLocator(poolRef string, oldAllocator, newAllocator SIDAllocator) {
	if len(m.subscribers) > 0 {
		for _, subscriber := range m.subscribers {
			subscriber.OnUpdateLocator(poolRef, oldAllocator, newAllocator)
		}
	}
	m.allocators[poolRef] = newAllocator
}

// Handle locator delete. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onDeleteLocator(poolRef string, oldAllocator SIDAllocator) {
	if len(m.subscribers) > 0 {
		for _, subscriber := range m.subscribers {
			subscriber.OnDeleteLocator(poolRef, oldAllocator)
		}
	}
	delete(m.allocators, poolRef)
}

// Restore existing allocations from k8s resource status
func (m *sidManager) restoreAllocations(ctx context.Context, r *v1alpha1.IsovalentSRv6SIDManager) {
	var (
		restoredSIDs = 0
		staleSIDs    = 0
		errorSIDs    = 0
		errs         error
	)

	// No existing allocation
	if r.Status == nil {
		return
	}

	smLog.Info("Restoring existing SID allocations")

	m.allocatorsLock.RLock()
	defer m.allocatorsLock.RUnlock()

	for _, sa := range r.Status.SIDAllocations {
		if allocator, ok := m.allocators[sa.PoolRef]; ok {
			for _, sid := range sa.SIDs {
				addr, err := netip.ParseAddr(sid.SID.Addr)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot parse SID on the status: %w", err))
					continue
				}

				structure, err := types.NewSIDStructure(
					sid.SID.Structure.LocatorBlockLenBits,
					sid.SID.Structure.LocatorNodeLenBits,
					sid.SID.Structure.FunctionLenBits,
					sid.SID.Structure.ArgumentLenBits,
				)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot parse SID Structure on the status: %w", err))
					continue
				}

				s, err := types.NewSID(addr, structure)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot create SID from SID and SID Structure on the status: %w", err))
					continue
				}

				// Check locator, SID structure and behavior
				// type mismatch. If there's a mismatch, maybe
				// an old pool updated while Cilium is
				// stopping. We can ignore this here. So that
				// it will be deleted from the status in the
				// next sync.
				if s.AsLocator() != *allocator.Locator() || types.BehaviorTypeFromString(sid.BehaviorType) != allocator.BehaviorType() {
					staleSIDs++
					continue
				}

				if _, err = allocator.Allocate(addr, sid.Owner, sid.MetaData, types.BehaviorFromString(sid.Behavior)); err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("allocation error: %w", err))
					continue
				}
				restoredSIDs++
			}
		} else {
			// Allocation exists, but there's no allocator (locator
			// pool). Maybe an old pool deleted while Cilium is
			// stopping. We can ignore this here. So that it will
			// be deleted from the status in the next sync.
			staleSIDs++
			continue
		}
	}

	smLog.Infof("Finish restoring existing SID allocations (restored: %d, stale: %d, error: %d)", restoredSIDs, staleSIDs, errorSIDs)
	if errs != nil {
		smLog.WithError(errs).Warn("Error occurred while restoring")
	}
}

// Delete all allocators. We don't have to schedule sync here since we don't
// have resource to sync anymore.
func (m *sidManager) deleteAllAllocators(r *v1alpha1.IsovalentSRv6SIDManager) {
	m.subscribersLock.RLock()
	defer m.subscribersLock.RUnlock()

	m.allocatorsLock.Lock()
	defer m.allocatorsLock.Unlock()

	for poolRef, allocator := range m.allocators {
		m.onDeleteLocator(poolRef, allocator)
	}

}

func (m *sidManager) runStatusReconciler(ctx context.Context) error {
	smLog.Info("Starting SID Manager status reconciler")

	defer m.wg.Done()

	// In case of the state synchronization failure, we retry with
	// exponential backoff.
	backoff := backoff.Exponential{
		// No specific reason for choosing value, but at least
		// make it predictable (by default, there is no limit).
		Max: 90 * time.Minute,
	}

	retrying := false
	for {
		select {
		case <-m.stateSyncCh:
			// We need this condition because otherwise, backoff.Wait always
			// backoffs for min time (1 second).
			if retrying {
				if err := backoff.Wait(ctx); err != nil {
					// The only possible error case here is context expiration.
					// In that case, we should return.
					return nil
				}
			}

			if err := m.reconcileStatus(ctx); err != nil {
				// Generate warning only for the first retry. Otherwise, it's too noisy.
				if !retrying {
					smLog.WithError(err).Warn("State synchronization failed. Retrying with backoff.")
					retrying = true
				} else {
					// This is for debugging
					smLog.WithError(err).Warn("State synchronization failed. Retrying with backoff.")
				}
				m.scheduleStateSync()
			} else {
				// Reset backoff on success
				if retrying {
					retrying = false
					backoff.Reset()
				}
			}
		case <-ctx.Done():
			smLog.Info("Stopping SID Manager status reconciler")
			return nil
		}
	}
}

func (m *sidManager) reconcileStatus(ctx context.Context) error {
	smLog.Debug("Synchronizing allocation state to k8s resource")

	status := v1alpha1.IsovalentSRv6SIDManagerStatus{
		SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{},
	}

	m.allocatorsLock.RLock()

	for poolName, allocator := range m.allocators {
		sis := allocator.AllocatedSIDs("")
		if len(sis) == 0 {
			continue
		}
		allocation := v1alpha1.IsovalentSRv6SIDAllocation{
			PoolRef: poolName,
		}
		for _, si := range sis {
			allocation.SIDs = append(allocation.SIDs, m.sidInfoToResource(si))
		}
		status.SIDAllocations = append(status.SIDAllocations, &allocation)
	}

	m.allocatorsLock.RUnlock()

	// Sort lists for the better status visibility
	slices.SortFunc(status.SIDAllocations, func(a, b *v1alpha1.IsovalentSRv6SIDAllocation) bool {
		return strings.Compare(a.PoolRef, b.PoolRef) == -1
	})
	for _, allocation := range status.SIDAllocations {
		slices.SortFunc(allocation.SIDs, func(a, b *v1alpha1.IsovalentSRv6SIDInfo) bool {
			return strings.Compare(a.SID.Addr, b.SID.Addr) == -1
		})
	}

	patch := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: &status,
		},
	}

	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal patch")
	}

	_, err = m.clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Patch(
		ctx, nodeTypes.GetName(), k8sTypes.JSONPatchType, patchJSON,
		metav1.PatchOptions{FieldManager: SRv6SIDManagerSubsys}, "status")
	if err != nil {
		return fmt.Errorf("failed to patch resource: %w", err)
	}

	smLog.Debug("Successfully synchronized the allocation state to k8s resource")

	return nil
}

// locatorFromResource converts locator on the k8s resource to internal Locator structure
func (m *sidManager) locatorFromResource(r *v1alpha1.IsovalentSRv6Locator) (*types.Locator, error) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, err
	}

	structure, err := types.NewSIDStructure(
		r.Structure.LocatorBlockLenBits,
		r.Structure.LocatorNodeLenBits,
		r.Structure.FunctionLenBits,
		r.Structure.ArgumentLenBits,
	)
	if err != nil {
		return nil, err
	}

	locator, err := types.NewLocator(prefix, structure)
	if err != nil {
		return nil, err
	}

	return locator, nil
}

// sidToResource converts internal SID structure to SID on k8s resource
func (m *sidManager) sidInfoToResource(si *SIDInfo) *v1alpha1.IsovalentSRv6SIDInfo {
	sid := v1alpha1.IsovalentSRv6SID{
		Addr: si.SID.Addr.String(),
		Structure: v1alpha1.IsovalentSRv6SIDStructure{
			LocatorBlockLenBits: si.SID.Structure().LocatorBlockLenBits(),
			LocatorNodeLenBits:  si.SID.Structure().LocatorNodeLenBits(),
			FunctionLenBits:     si.SID.Structure().FunctionLenBits(),
			ArgumentLenBits:     si.SID.Structure().ArgumentLenBits(),
		},
	}
	return &v1alpha1.IsovalentSRv6SIDInfo{
		Owner:        si.Owner,
		MetaData:     si.MetaData,
		SID:          sid,
		BehaviorType: si.BehaviorType.String(),
		Behavior:     si.Behavior.String(),
	}
}

// scheduleStateSync schedules allocation state synchronization to k8s resource
func (m *sidManager) scheduleStateSync() {
	select {
	case m.stateSyncCh <- struct{}{}:
		smLog.Debug("Scheduled state sync")
	default:
		smLog.Debug("State sync is already scheduled. Skipping.")
	}
}

// LocalIsovalentSRv6SIDManagerResource is a Resource[T] for the local
// SIDManager resource (SIDManager resource that its name is the same as local
// node name.
type LocalIsovalentSRv6SIDManagerResource resource.Resource[*v1alpha1.IsovalentSRv6SIDManager]

func NewLocalIsovalentSRv6SIDManagerResource(lc hive.Lifecycle, cs client.Clientset) (LocalIsovalentSRv6SIDManagerResource, error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*v1alpha1.IsovalentSRv6SIDManagerList](cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers()),
		func(opts *metav1.ListOptions) {
			// Note: FakeClientset doesn't handle this filtering
			opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
		},
	)
	return resource.New[*v1alpha1.IsovalentSRv6SIDManager](lc, lw, resource.WithMetric("IsovalentSRv6SIDManager")), nil
}
