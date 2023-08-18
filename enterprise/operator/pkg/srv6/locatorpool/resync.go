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
)

// resync works as following
// 1 - Listen on node event till sync received and populate lpm.nodeAllocations map
// 2 - Listen on pool events
// 2.1 - On pool upsert events
// 2.1.1 - Check existing SIDManagers, if pool exists, sync NodeID. If pool does not exist, create pool in local state and do nothing.
// 2.1.2 - Note : We do not create new allocations in SIDManagers here, as we need to discover all allocated node IDs first.
// 2.2 - On pool delete events
// 2.2.1 - Remove pool from local state.
// 2.3 - On pool sync event
// 2.3.1 - By this time, we have all expected allocations pools and nodes in local state.
// 2.3.2 - Add/remove SIDManager based on nodes.
// 2.3.2 - Update SIDManagers based on local pool state.
func (lpm *LocatorPoolManager) resync(ctx context.Context) {
nodeEventLoop:
	for event := range lpm.nodeEvents {
		lpm.logger.Infof("Resync: node event %s %s", event.Kind, event.Key)

		switch event.Kind {
		case resource.Sync:
			lpm.logger.Info("Nodes synchronized")
			event.Done(nil)
			break nodeEventLoop

		case resource.Upsert:
			lpm.nodeAllocations[event.Object.Name] = make(allocations)
		case resource.Delete:
			delete(lpm.nodeAllocations, event.Object.Name)
		}

		event.Done(nil)
	}

poolEventLoop:
	for event := range lpm.poolEvents {
		lpm.logger.Infof("Resync: pool event %s %s", event.Kind, event.Key)

		sidManagerStore, err := lpm.srv6SIDManagerResource.Store(ctx)
		if err != nil {
			lpm.logger.Errorf("failed to get SRv6SIDManagers from store: %w", err)
			event.Done(err)
			continue
		}
		sidManagers := sidManagerStore.List()

		switch event.Kind {
		case resource.Sync:
			lpm.syncSIDManagers(ctx, sidManagers)
			event.Done(nil)
			break poolEventLoop

		case resource.Upsert:
			err = lpm.createPoolAndSyncNodeIDs(event.Object, sidManagers)
			if err != nil {
				lpm.logger.Errorf("failed to reallocate pool: %w", err)
			}
		case resource.Delete:
			lpm.deletePoolState(event.Object)
		}
		event.Done(err)
	}

	lpm.logger.Info("Pools synchronized")
	lpm.synced = true
}

func (lpm *LocatorPoolManager) createPoolAndSyncNodeIDs(pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, sidManagers []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager) error {
	prefix, sidStructure, err := lpm.parsePool(pool)
	if err != nil {
		return fmt.Errorf("parsePool: %w", err)
	}

	p, err := newPool(poolConfig{pool.Name, prefix, sidStructure})
	if err != nil {
		return fmt.Errorf("newPool: %w", err)
	}

	// go over each manager and reserve its node ID
	for _, sidManager := range sidManagers {
		// we do not have this node locally, skip it
		if _, exists := lpm.nodeAllocations[sidManager.Name]; !exists {
			continue
		}

		for _, allocations := range sidManager.Spec.LocatorAllocations {
			// we only expect 1 item in Locators
			if allocations.PoolRef == pool.Name && len(allocations.Locators) == 1 {
				err := lpm.syncPoolWithAPI(p, sidManager.Name, allocations.Locators[0])
				if err != nil {
					// on failure to sync, we log error and continue. Failed pools will get new allocations at end of resync.
					lpm.logger.Warnf("failed to sync state SID Manager %s pool %s: %w", sidManager.Name, pool.Name, err)
				}
				break
			}
		}
	}

	// add pool to local state
	lpm.pools[pool.Name] = p

	return nil
}

// syncPoolWithAPI will sync the local pool with the node locator from k8s API.
// If there is mismatch in the node locator, it will be skipped.
func (lpm *LocatorPoolManager) syncPoolWithAPI(p LocatorPool, nodeRef string, nodeAPILocator *isovalent_api_v1alpha1.IsovalentSRv6Locator) error {
	nodeLoc, err := fromAPILocator(nodeAPILocator)
	if err != nil {
		return fmt.Errorf("failed to parse node locator %v: %w", nodeAPILocator, err)
	}

	err = p.Allocate(nodeLoc)
	if err != nil {
		return fmt.Errorf("failed to allocate node ID from existing SID Manager %s: %w", nodeRef, err)
	}

	lpm.nodeAllocations[nodeRef][p.GetName()] = nodeLoc
	lpm.logger.Debugf("re-allocating locator %s from pool %s to node %s", nodeLoc.Prefix, p.GetName(), nodeRef)

	return nil
}

func fromAPILocator(loc *isovalent_api_v1alpha1.IsovalentSRv6Locator) (*types.Locator, error) {
	nodeSIDPrefix, err := netip.ParsePrefix(loc.Prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix of existing SID Manager %s: %w", loc.Prefix, err)
	}

	nodeSIDStructure, err := types.NewSIDStructure(loc.Structure.LocatorBlockLenBits,
		loc.Structure.LocatorNodeLenBits,
		loc.Structure.FunctionLenBits,
		loc.Structure.ArgumentLenBits)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SID structure of existing SID Manager %v: %w", loc.Structure, err)
	}

	return types.NewLocator(nodeSIDPrefix, nodeSIDStructure)
}

func (lpm *LocatorPoolManager) syncSIDManagers(ctx context.Context, sidManagers []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager) {
	var (
		toCreateNodes []string
		toDeleteNodes []string
		toUpdateNodes []string
	)

	runningSIDManagers := make(map[string]struct{})
	for _, node := range sidManagers {
		runningSIDManagers[node.Name] = struct{}{}
	}

	for node := range lpm.nodeAllocations {
		_, found := runningSIDManagers[node]
		if !found {
			toCreateNodes = append(toCreateNodes, node)
		} else {
			toUpdateNodes = append(toUpdateNodes, node)
		}
	}

	for runningSIDManager := range runningSIDManagers {
		_, found := lpm.nodeAllocations[runningSIDManager]
		if !found {
			toDeleteNodes = append(toDeleteNodes, runningSIDManager)
		}
	}

	for _, node := range toCreateNodes {
		err := lpm.addNode(ctx, node)
		if err != nil {
			// log error and continue
			lpm.logger.Errorf("failed to add node %s: %w", node, err)
		}
	}

	for _, node := range toDeleteNodes {
		err := lpm.deleteNode(ctx, node)
		if err != nil {
			// log error and continue
			lpm.logger.Errorf("failed to add node %s: %w", node, err)
		}
	}

	// update existing nodes with latest local state
	for _, nodeRef := range toUpdateNodes {
		err := lpm.updateNodeAllocations(ctx, nodeRef)
		if err != nil {
			// log error and continue
			lpm.logger.Errorf("failed to update node %s: %w", nodeRef, err)
		}
	}
}
