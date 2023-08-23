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
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSubscriber struct {
	OnAddCount    int
	OnUpdateCount int
	OnDeleteCount int
}

func (f *fakeSubscriber) OnAddLocator(poolName string, allocator SIDAllocator) {
	f.OnAddCount++
}

func (f *fakeSubscriber) OnUpdateLocator(poolName string, oldAllocator, newAllocator SIDAllocator) {
	f.OnUpdateCount++
}

func (f *fakeSubscriber) OnDeleteLocator(poolName string, allocator SIDAllocator) {
	f.OnDeleteCount++
}

func (f *fakeSubscriber) Reset() {
	f.OnAddCount = 0
	f.OnUpdateCount = 0
	f.OnDeleteCount = 0
}

func TestSIDManager(t *testing.T) {
	smLog.Logger.SetLevel(logrus.DebugLevel)

	poolName1 := "pool1"
	poolName2 := "pool2"
	structure1 := types.MustNewSIDStructure(32, 16, 16, 0)
	structure2 := types.MustNewSIDStructure(32, 16, 24, 0)
	locator1 := types.MustNewLocator(netip.MustParsePrefix("fd00:1:1::/48"), structure1)
	locator2 := types.MustNewLocator(netip.MustParsePrefix("fd00:2:1::/48"), structure1)
	locator3 := types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"), structure1)
	locator4 := types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"), structure2)

	resourceStructure1 := v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: structure1.LocatorBlockLenBits(),
		LocatorNodeLenBits:  structure1.LocatorNodeLenBits(),
		FunctionLenBits:     structure1.FunctionLenBits(),
		ArgumentLenBits:     structure1.ArgumentLenBits(),
	}

	resourceStructure2 := v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: structure2.LocatorBlockLenBits(),
		LocatorNodeLenBits:  structure2.LocatorNodeLenBits(),
		FunctionLenBits:     structure2.FunctionLenBits(),
		ArgumentLenBits:     structure2.ArgumentLenBits(),
	}

	createManager := func(t *testing.T, m *v1alpha1.IsovalentSRv6SIDManager) (SIDManager,
		resource.Store[*v1alpha1.IsovalentSRv6SIDManager], k8sclient.Clientset) {
		lc := hivetest.Lifecycle(t)

		fc, cs := k8sclient.NewFakeClientset()

		fc.CiliumFakeClientset.Tracker().Create(
			v1alpha1.SchemeGroupVersion.WithResource("isovalentsrv6sidmanagers"),
			m.DeepCopy(), "",
		)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)

		dc := &option.DaemonConfig{EnableSRv6: true}

		resource := NewLocalIsovalentSRv6SIDManagerResource(dc, lc, cs)

		store, err := resource.Store(ctx)
		require.NoError(t, err)

		sidManagerPromise := NewSIDManagerPromise(sidManagerParams{
			Lc:       lc,
			Cs:       cs,
			Dc:       dc,
			Resource: resource,
		})

		sidManager, err := sidManagerPromise.Await(ctx)
		require.NoError(t, err)

		cancel()

		return sidManager, store, cs
	}

	t.Run("TestSpecReconciliation", func(t *testing.T) {
		manager, _, cs := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{},
		})

		t.Run("NoLocator", func(t *testing.T) {
			require.Error(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				require.Fail(t, "ManageSID should fail against the pool doesn't exist")
				return false, nil
			}))
		})

		t.Run("AddOneLocator", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					return false, nil
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorPrefix", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator3.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if *allocator.Locator() == *locator3 {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorStructure", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator4.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if *allocator.Locator() == *locator4 {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorBehaviorType", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "uSID",
										Prefix:       locator4.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if *allocator.Locator() == *locator4 && allocator.BehaviorType() == types.BehaviorTypeUSID {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("AddOneMoreLocators", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err != nil {
					return false
				}
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec reconciliation didn't happen")
		})

		t.Run("DeleteLocators", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err == nil {
					return false
				}
				if err := manager.ManageSID(poolName2, func(allocator SIDAllocator) (bool, error) { return false, nil }); err == nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec reconciliation didn't happen")
		})
	})

	t.Run("TestStatusReconciliation", func(t *testing.T) {
		manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
				LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
					{
						PoolRef: poolName1,
						Locators: []*v1alpha1.IsovalentSRv6Locator{
							{
								BehaviorType: "Base",
								Prefix:       locator1.Prefix.String(),
								Structure:    resourceStructure1,
							},
						},
					},
				},
			},
		})

		t.Run("AllocateSIDWithManageSID", func(t *testing.T) {
			var allocatedSID *SIDInfo
			require.NoError(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sid, err := allocator.Allocate(netip.MustParseAddr("fd00:1:1:1::"), "test", "test", types.BehaviorEndDT4)
				require.NoError(t, err)
				allocatedSID = sid
				return true, nil
			}))
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if len(r.Status.SIDAllocations) != 1 {
					return false
				}
				require.Equal(t, poolName1, r.Status.SIDAllocations[0].PoolRef, "Pool name mismatched between status and allocation")
				require.Len(t, r.Status.SIDAllocations[0].SIDs, 1, "More than one SID is on status")
				require.Equal(t, allocatedSID.SID.Addr.String(), r.Status.SIDAllocations[0].SIDs[0].SID.Addr, "SID mismatched between status and allocation")
				return true
			}, time.Second*3, time.Millisecond*200, "Status reconciliation didn't happen")
		})

		t.Run("ReleaseSIDWithManageSID", func(t *testing.T) {
			require.NoError(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				err := allocator.Release(netip.MustParseAddr("fd00:1:1:1::"))
				require.NoError(t, err)
				return true, nil
			}))
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				return r.Status == nil || len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Status reconciliation didn't happen")
		})

		t.Run("ManageSIDReturnsFalse", func(t *testing.T) {
			require.NoError(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				_, err := allocator.Allocate(netip.MustParseAddr("fd00:1:1:1::"), "test", "test", types.BehaviorEndDT4)
				require.NoError(t, err)
				return false, nil
			}))
			require.Never(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				return r.Status != nil && len(r.Status.SIDAllocations) != 0
			}, time.Second*2, time.Millisecond*200, "Status reconciliation happened for the ManageSID returns false")
		})
	})

	t.Run("TestRestore", func(t *testing.T) {
		t.Run("ValidSID", func(t *testing.T) {
			manager, _, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     16,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "Base",
									Behavior:     "End.DT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 1)
				require.Equal(t, netip.MustParseAddr("fd00:1:1:1::"), sids[0].SID.Addr, "Restored allocation doesn't match to status")
				require.Equal(t, "test", sids[0].Owner, "Restored owner doesn't match to status")
				require.Equal(t, "test1", sids[0].MetaData, "Restored metadata doesn't match to status")
				require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior, "Restored Behavior doesn't match to status")
				return false, nil
			})
		})

		t.Run("StaleSIDStructureMismatch", func(t *testing.T) {
			manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     24,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "Base",
									Behavior:     "End.DT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 0, "Stale allocation restored to the allocator")
				return false, nil
			})
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if r.Status == nil {
					return false
				}
				return len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Stale allocation restored to the status")
		})

		t.Run("StaleSIDBehaviorTypeMismatch", func(t *testing.T) {
			manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     16,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "uSID",
									Behavior:     "uDT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 0, "Stale allocation restored to the allocator")
				return false, nil
			})
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if r.Status == nil {
					return false
				}
				return len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Stale allocation restored to the status")
		})
	})

	t.Run("TestSubscription", func(t *testing.T) {
		manager, _, cs := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
				LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
					{
						PoolRef: poolName1,
						Locators: []*v1alpha1.IsovalentSRv6Locator{
							{
								BehaviorType: "Base",
								Prefix:       locator1.Prefix.String(),
								Structure:    resourceStructure1,
							},
						},
					},
				},
			},
		})

		subscriber := fakeSubscriber{}
		manager.Subscribe("fakeSubscriber", &subscriber, func() {})

		t.Run("InitialAdd", func(t *testing.T) {
			defer subscriber.Reset()
			require.Equal(t, 1, subscriber.OnAddCount, "Subscribe didn't call initial OnAddLocator")
		})

		t.Run("OnAddLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnAddCount == 1
			}, time.Second*3, time.Millisecond*200, "OnAddLocator didn't happen")
		})

		t.Run("OnUpdateLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnUpdateCount == 1
			}, time.Second*3, time.Millisecond*200, "OnUpdateLocator didn't happen")
		})

		t.Run("OnDeleteLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnDeleteCount == 2
			}, time.Second*3, time.Millisecond*200, "OnDeleteLocator didn't happen twice")
		})
	})
}
