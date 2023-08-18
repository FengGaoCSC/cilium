//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package locatorpool

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func (lpm *LocatorPoolManager) handleNodeEvent(ctx context.Context, event resource.Event[*slimv1.Node]) {
	lpm.logger.Debugf("node event %s: %s", event.Kind, event.Key)

	var err error
	switch event.Kind {
	case resource.Upsert:
		err = lpm.addNode(ctx, event.Object.Name)
		if err != nil {
			err = fmt.Errorf("failed to upsert: %w", err)
			lpm.logger.WithError(err).Error("failed to upsert node")
		}

	case resource.Delete:
		err = lpm.deleteNode(ctx, event.Object.Name)
		if err != nil {
			err = fmt.Errorf("failed to delete: %w", err)
			lpm.logger.WithError(err).Error("failed to delete node")
		}
	}

	event.Done(err)
}

func (lpm *LocatorPoolManager) addNode(ctx context.Context, nodeRef string) error {
	if _, exists := lpm.nodeAllocations[nodeRef]; exists {
		return nil
	}

	lpm.logger.Infof("adding node %s", nodeRef)
	lpm.nodeAllocations[nodeRef] = make(allocations)

	return lpm.updateNodeAllocations(ctx, nodeRef)
}

func (lpm *LocatorPoolManager) updateNodeAllocations(ctx context.Context, nodeRef string) error {
	for _, p := range lpm.pools {
		_, exists := lpm.nodeAllocations[nodeRef][p.GetName()]
		if exists {
			// pool locator already assigned to node
			continue
		}

		loc, err := p.AllocateNext()
		if err != nil {
			// log error and continue with other pools
			lpm.logger.Errorf("pool.AllocateNext: %w", err)
			continue
		}
		lpm.nodeAllocations[nodeRef][p.GetName()] = loc
		lpm.logger.Debugf("allocating locator %s from pool %s to node %s", loc.Prefix, p.GetName(), nodeRef)
	}

	return lpm.upsertSIDManager(ctx, nodeRef)
}

func (lpm *LocatorPoolManager) deleteNode(ctx context.Context, nodeRef string) error {
	lpm.logger.Infof("deleting node %s", nodeRef)

	// clean up local resources - idempotent
	n, exists := lpm.nodeAllocations[nodeRef]
	if exists {
		for poolName, loc := range n {
			pool, exist := lpm.pools[poolName]
			if exist {
				pool.Release(loc)
			}
		}

		delete(lpm.nodeAllocations, nodeRef)
	}

	// delete from k8s
	return lpm.deleteSIDManager(ctx, nodeRef)
}

func (lpm *LocatorPoolManager) handlePoolEvent(ctx context.Context, event resource.Event[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool]) {
	lpm.logger.Infof("pool event %s: %s", event.Kind, event.Key)

	var err error
	switch event.Kind {
	case resource.Upsert:
		err = lpm.addPool(ctx, event.Object)
		if err != nil {
			err = fmt.Errorf("failed to upsert: %w", err)
			lpm.logger.WithError(err).Error("failed to upsert locator pool")
		}

	case resource.Delete:
		err = lpm.deletePool(ctx, event.Object)
		if err != nil {
			err = fmt.Errorf("failed to delete: %w", err)
			lpm.logger.WithError(err).Error("failed to delete locator pool")
		}
	}

	event.Done(err)
}

// addPool handles locator pool upsert events. On update, we overwrite the pool, modifications in SID Structure or prefix result in
// overwriting of SIDManager resource.
func (lpm *LocatorPoolManager) addPool(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool) error {
	prefix, sidStructure, err := lpm.parsePool(pool)
	if err != nil {
		return fmt.Errorf("parsePool: %w", err)
	}

	// pool is not overlapping with existing pools
	for _, p := range lpm.pools {
		if p.GetName() == pool.Name {
			// skip self
			continue
		}
		if p.GetPrefix().Overlaps(prefix) {
			return ErrOverlappingPrefix
		}
	}

	p, err := newPool(poolConfig{pool.Name, prefix, sidStructure})
	if err != nil {
		return fmt.Errorf("newPool: %w", err)
	}

	// update allocations in existing nodeAllocations
	for nodeRef := range lpm.nodeAllocations {
		loc, err := p.AllocateNext()
		if err != nil {
			return fmt.Errorf("pool.AllocateNext: %w", err)
		}
		lpm.nodeAllocations[nodeRef][pool.Name] = loc
		lpm.logger.Debugf("allocating locator %s from pool %s to node %s", loc.Prefix, pool.Name, nodeRef)
	}

	// update pool
	lpm.pools[pool.Name] = p

	// update all SID managers
	for nodeRef := range lpm.nodeAllocations {
		err = lpm.upsertSIDManager(ctx, nodeRef)
		if err != nil {
			return fmt.Errorf("upsertSIDManager: %w", err)
		}
	}
	return nil
}

func (lpm *LocatorPoolManager) parsePool(pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool) (prefix netip.Prefix, sidStructure *types.SIDStructure, err error) {
	// validate prefix
	prefix, err = netip.ParsePrefix(pool.Spec.Prefix)
	if err != nil {
		err = fmt.Errorf("prefix %s is invalid: %w", pool.Spec.Prefix, err)
		return
	}

	sidStructure, err = types.NewSIDStructure(pool.Spec.Structure.LocatorBlockLenBits,
		pool.Spec.Structure.LocatorNodeLenBits,
		pool.Spec.Structure.FunctionLenBits,
		pool.Spec.Structure.ArgumentLenBits)
	if err != nil {
		err = fmt.Errorf("failed to create SID structure: %s - %w", ErrInvalidSID, err)
		return
	}

	return
}

func (lpm *LocatorPoolManager) deletePool(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool) error {
	// update local state
	lpm.deletePoolState(pool)

	// update all SID managers
	for nodeRef := range lpm.nodeAllocations {
		err := lpm.upsertSIDManager(ctx, nodeRef)
		if err != nil {
			return fmt.Errorf("upsertSIDManager: %w", err)
		}
	}
	return nil
}

func (lpm *LocatorPoolManager) deletePoolState(pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool) {
	p, exists := lpm.pools[pool.Name]
	if !exists {
		return
	}

	// remove nodeAllocations
	for _, locators := range lpm.nodeAllocations {
		loc, exists := locators[pool.Name]
		if exists {
			p.Release(loc)
			delete(locators, pool.Name)
		}
	}
	delete(lpm.pools, pool.Name)
}
