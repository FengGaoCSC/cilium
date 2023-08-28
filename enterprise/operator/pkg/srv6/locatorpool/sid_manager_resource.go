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

	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// upsertSIDManager syncs local pool state with given node's SRv6SIDManager resource
func (lpm *LocatorPoolManager) upsertSIDManager(ctx context.Context, nodeRef string) error {
	store, err := lpm.srv6SIDManagerResource.Store(ctx)
	if err != nil {
		return err
	}

	oldSM, exist, err := store.Get(&isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeRef,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get SRv6SIDManager resource from store: %w", err)
	}

	if exist {
		return lpm.updateSIDManager(ctx, oldSM)
	}

	return lpm.createSIDManager(ctx, nodeRef)
}

// createSIDManager creates a new SRv6SIDManager resource for a given node and pool
func (lpm *LocatorPoolManager) createSIDManager(ctx context.Context, nodeRef string) error {
	sm := &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeRef,
		},
		TypeMeta: metav1.TypeMeta{
			APIVersion: "isovalent.com/v1alpha1",
			Kind:       "IsovalentSRv6SIDManager",
		},
		Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
			LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{},
		},
	}
	pools := lpm.populateAPISIDManager(sm)

	lpm.logger.WithFields(logrus.Fields{
		"node":  nodeRef,
		"pools": pools,
	}).Info("creating SRv6SIDManager resource")

	_, err := lpm.srv6SIDManagerClient.Create(ctx, sm, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create SRv6SIDManager resource: %w", err)
	}

	return nil
}

// updateSIDManager updates an existing SRv6SIDManager resource for a given node and pool
func (lpm *LocatorPoolManager) updateSIDManager(ctx context.Context, sm *isovalent_api_v1alpha1.IsovalentSRv6SIDManager) error {
	pools := lpm.populateAPISIDManager(sm)

	lpm.logger.WithFields(logrus.Fields{
		"node":  sm.Name,
		"pools": pools,
	}).Info("updating SRv6SIDManager resource")

	_, err := lpm.srv6SIDManagerClient.Update(ctx, sm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update SRv6SIDManager resource: %w", err)
	}

	return nil
}

// deleteSIDManager deletes SRv6SIDManager resource
func (lpm *LocatorPoolManager) deleteSIDManager(ctx context.Context, nodeRef string) error {
	_, err := lpm.srv6SIDManagerClient.Get(ctx, nodeRef, metav1.GetOptions{})
	if err != nil {
		// If the resource is not found, it means that it was already deleted
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get SRv6 SID Manager resource: %w", err)
	}

	lpm.logger.WithFields(logrus.Fields{
		"node": nodeRef,
	}).Info("deleting SRv6 SID Manager resource")

	err = lpm.srv6SIDManagerClient.Delete(ctx, nodeRef, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to update SRv6 SID manager resource after delete: %w", err)
	}

	return nil
}

func (lpm *LocatorPoolManager) populateAPISIDManager(sm *isovalent_api_v1alpha1.IsovalentSRv6SIDManager) []string {
	var resultingPools []string

	for poolName, loc := range lpm.nodeAllocations[sm.Name] {
		found := false
		for i := 0; i < len(sm.Spec.LocatorAllocations); i++ {
			if sm.Spec.LocatorAllocations[i].PoolRef == poolName {
				// update existing allocation
				sm.Spec.LocatorAllocations[i].Locators = []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
					toAPILocator(loc),
				}
				found = true
				break
			}
		}

		if !found {
			// add new allocation
			sm.Spec.LocatorAllocations = append(sm.Spec.LocatorAllocations, &isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
				PoolRef:  poolName,
				Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{toAPILocator(loc)},
			})
		}
	}

	// delete allocations for pools that are not present in local state
	nodeAllocations, exists := lpm.nodeAllocations[sm.Name]
	if !exists {
		// if locally node does not exist, then all allocations should be deleted
		sm.Spec.LocatorAllocations = []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{}
		return resultingPools
	}

	for i := 0; i < len(sm.Spec.LocatorAllocations); i++ {
		if _, exists := nodeAllocations[sm.Spec.LocatorAllocations[i].PoolRef]; !exists {
			// pool is missing locally, we should delete it from the list
			sm.Spec.LocatorAllocations[i] = sm.Spec.LocatorAllocations[len(sm.Spec.LocatorAllocations)-1]
			sm.Spec.LocatorAllocations = sm.Spec.LocatorAllocations[:len(sm.Spec.LocatorAllocations)-1]
		}
	}

	for _, pool := range sm.Spec.LocatorAllocations {
		resultingPools = append(resultingPools, pool.PoolRef)
	}
	return resultingPools
}

func toAPILocator(loc *LocatorInfo) *isovalent_api_v1alpha1.IsovalentSRv6Locator {
	return &isovalent_api_v1alpha1.IsovalentSRv6Locator{
		Prefix: loc.Prefix.String(),
		Structure: isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
			LocatorBlockLenBits: loc.Structure().LocatorBlockLenBits(),
			LocatorNodeLenBits:  loc.Structure().LocatorNodeLenBits(),
			FunctionLenBits:     loc.Structure().FunctionLenBits(),
			ArgumentLenBits:     loc.Structure().ArgumentLenBits(),
		},
		BehaviorType: loc.BehaviorType.String(),
	}
}
