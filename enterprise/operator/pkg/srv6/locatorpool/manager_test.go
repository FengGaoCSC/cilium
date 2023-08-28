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
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_core_v1_client "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	maxTestDuration = 5 * time.Second
)

// various SID structures used in the tests
var (
	sid_40_24_16 = isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: 40,
		LocatorNodeLenBits:  24,
		FunctionLenBits:     16,
		ArgumentLenBits:     0,
	}
	types_sid_40_24_16 = types.MustNewSIDStructure(
		sid_40_24_16.LocatorBlockLenBits,
		sid_40_24_16.LocatorNodeLenBits,
		sid_40_24_16.FunctionLenBits,
		sid_40_24_16.ArgumentLenBits,
	)

	sid_40_16_16 = isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: 40,
		LocatorNodeLenBits:  16,
		FunctionLenBits:     16,
		ArgumentLenBits:     0,
	}

	sid_invalid_130 = isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: 40,
		LocatorNodeLenBits:  40,
		FunctionLenBits:     40,
		ArgumentLenBits:     10,
	}
)

type initialConfig struct {
	locatorpools []*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool
	sidmanagers  []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager
}

type fixture struct {
	hive                 *hive.Hive
	manager              *LocatorPoolManager
	fakeClientSet        *k8sClient.FakeClientset
	locatorPoolClient    isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface
	srv6SIDManagerClient isovalent_client_v1alpha1.IsovalentSRv6SIDManagerInterface
	nodeResClient        slim_core_v1_client.NodeInterface
}

func newFixture() *fixture {
	logrus.SetLevel(logrus.DebugLevel)

	f := &fixture{}

	f.fakeClientSet, _ = k8sClient.NewFakeClientset()
	f.locatorPoolClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentSRv6LocatorPools()
	f.srv6SIDManagerClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
	f.nodeResClient = f.fakeClientSet.SlimFakeClientset.CoreV1().Nodes()

	f.hive = hive.New(
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager] {
			return resource.New[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager](
				lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentSRv6SIDManagerList](
					c.IsovalentV1alpha1().IsovalentSRv6SIDManagers(),
				),
			)
		}),

		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool] {
			return resource.New[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool](
				lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolList](
					c.IsovalentV1alpha1().IsovalentSRv6LocatorPools(),
				),
			)
		}),

		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*slim_core_v1.Node] {
			return resource.New[*slim_core_v1.Node](
				lc, utils.ListerWatcherFromTyped[*slim_core_v1.NodeList](
					c.Slim().CoreV1().Nodes(),
				),
			)
		}),

		cell.Provide(func() k8sClient.Clientset {
			return f.fakeClientSet
		}),

		cell.Invoke(func(locPoolManager *LocatorPoolManager) {
			f.manager = locPoolManager
		}),

		job.Cell,
		Cell,
	)

	// enable locator-pool
	hive.AddConfigOverride(f.hive, func(cfg *Config) { cfg.Enabled = true })

	return f
}

// Test_PoolValidations tests the LocatorPoolManager's locator pool prefix and sid validations
func Test_PoolValidations(t *testing.T) {
	tests := []struct {
		description     string
		pool            *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool
		expectedPoolErr error
	}{
		{
			description: "valid initial pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-1",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:1::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "Base",
				},
			},
			expectedPoolErr: nil,
		},
		{
			description: "invalid pool behavior",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-1",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:1::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "invalid",
				},
			},
			expectedPoolErr: ErrInvalidBehaviorType,
		},
		{
			description: "invalid pool prefix",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "10.10.10.0/24",
					Structure:    sid_40_24_16,
					BehaviorType: "Base",
				},
			},
			expectedPoolErr: ErrInvalidPrefix,
		},
		{
			description: "invalid pool prefix and SID combination",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2002:db8:1::/64",
					Structure:    sid_40_16_16,
					BehaviorType: "Base",
				},
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
		{
			description: "invalid locator pool SID, SID lengths exceed 128",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2002:db8:1::/48",
					Structure:    sid_invalid_130,
					BehaviorType: "Base",
				},
			},
			expectedPoolErr: ErrInvalidSID,
		},
		{
			description: "invalid prefix, prefix already used by another pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:1::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "Base",
				},
			},
			expectedPoolErr: ErrOverlappingPrefix,
		},
	}

	// initialize test fixture
	f := newFixture()
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	f.hive.Start(ctx)
	defer f.hive.Stop(ctx)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := f.manager.addPool(ctx, test.pool)
			if test.expectedPoolErr != nil {
				req.Error(err)
				req.Contains(err.Error(), test.expectedPoolErr.Error())
			} else {
				req.NoError(err)
			}
		})
	}
}

// Test_LocatorPoolResourceChanges tests the LocatorPoolManager's reaction to changes in the Node resources
func Test_NodeResourceChanges(t *testing.T) {
	poolPrefixLen := 48
	testLocPool := []*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "test-locator-pool-1",
			},
			Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
				Prefix:       "2001:db8:1::/48",
				Structure:    sid_40_24_16,
				BehaviorType: "Base",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "test-locator-pool-2",
			},
			Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
				Prefix:       "2001:db8:2::/48",
				Structure:    sid_40_24_16,
				BehaviorType: "Base",
			},
		},
	}

	steps := []struct {
		description     string
		node            *slim_core_v1.Node
		nodeOperation   func(ctx context.Context, node *slim_core_v1.Node, client slim_core_v1_client.NodeInterface) error
		expectedChanges []SIDManagerEvent
	}{
		{
			description: "add node",
			node:        &slim_core_v1.Node{ObjectMeta: slim_metav1.ObjectMeta{Name: "node1"}},
			nodeOperation: func(ctx context.Context, node *slim_core_v1.Node, client slim_core_v1_client.NodeInterface) error {
				_, err := client.Create(ctx, node, meta_v1.CreateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Added,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:2:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "update node, should be no-op",
			node: &slim_core_v1.Node{ObjectMeta: slim_metav1.ObjectMeta{
				Name:   "node1",
				Labels: map[string]string{"foo": "bar"},
			}},
			nodeOperation: func(ctx context.Context, node *slim_core_v1.Node, client slim_core_v1_client.NodeInterface) error {
				_, err := client.Update(ctx, node, meta_v1.UpdateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{},
		},
		{
			description: "delete node",
			node:        &slim_core_v1.Node{ObjectMeta: slim_metav1.ObjectMeta{Name: "node1"}},
			nodeOperation: func(ctx context.Context, node *slim_core_v1.Node, client slim_core_v1_client.NodeInterface) error {
				return client.Delete(ctx, node.Name, meta_v1.DeleteOptions{})
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Deleted,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:2:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// initialize test fixture
	f := newFixture()
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	f.hive.Start(ctx)
	defer f.hive.Stop(ctx)

	// initialize with test nodeAllocations
	for _, pool := range testLocPool {
		_, err := f.locatorPoolClient.Create(ctx, pool, meta_v1.CreateOptions{})
		req.NoError(err)
	}

	// wait for manager to synchronize
	req.Eventually(func() bool {
		return f.manager.synced
	}, maxTestDuration, time.Millisecond*100)

	// watch for SRv6SIDManagers
	watch, err := f.srv6SIDManagerClient.Watch(ctx, meta_v1.ListOptions{})
	req.NoError(err)
	defer watch.Stop()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			err := step.nodeOperation(ctx, step.node, f.nodeResClient)
			req.NoError(err)

			sidManagerEvents := collectEvents(req, ctx, watch.ResultChan(), len(step.expectedChanges))

			// check for any extra event in the channel
			select {
			case res := <-watch.ResultChan():
				resource, ok := res.Object.(*isovalent_api_v1alpha1.IsovalentSRv6SIDManager)
				req.True(ok)
				req.Failf("extra event received", "resource: %v", resource)
			default:
			}

			sameSIDManagers(req, poolPrefixLen, sidManagerEvents, step.expectedChanges)
		})
	}
}

// Test_LocatorPoolResourceChanges tests the LocatorPoolManager's reaction to changes in the LocatorPool resources
// Note this test case runs in steps, so there is dependency between the steps
func Test_LocatorPoolResourceChanges(t *testing.T) {
	testNodes := []string{"node1", "node2"}
	poolPrefixLen := 48

	steps := []struct {
		description     string
		pool            *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool
		poolOperation   func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error
		expectedChanges []SIDManagerEvent
	}{
		{
			description: "1 : create first pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-1",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:1::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "Base",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				_, err := client.Create(ctx, pool, meta_v1.CreateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Added,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
				{
					eventType: watch.Added,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "2. create second pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:2::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "Base",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				_, err := client.Create(ctx, pool, meta_v1.CreateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:2:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:2:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "3. update second pool prefix",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix:       "2001:db8:aaaa::/48",
					Structure:    sid_40_24_16,
					BehaviorType: "uSID",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				_, err := client.Update(ctx, pool, meta_v1.UpdateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:aaaa:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:aaaa:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "4. update second pool sid structure",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
				Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
					Prefix: "2001:db8:aaaa::/48",
					Structure: isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
						LocatorBlockLenBits: 40,
						LocatorNodeLenBits:  24,
						FunctionLenBits:     16,
						ArgumentLenBits:     16, // UPDATED
					},
					BehaviorType: "uSID",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				_, err := client.Update(ctx, pool, meta_v1.UpdateOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix: "2001:db8:aaaa:1::/64",
											Structure: isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
												LocatorBlockLenBits: 40,
												LocatorNodeLenBits:  24,
												FunctionLenBits:     16,
												ArgumentLenBits:     16, // UPDATED
											},
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "test-locator-pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix: "2001:db8:aaaa:2::/64",
											Structure: isovalent_api_v1alpha1.IsovalentSRv6SIDStructure{
												LocatorBlockLenBits: 40,
												LocatorNodeLenBits:  24,
												FunctionLenBits:     16,
												ArgumentLenBits:     16, // UPDATED
											},
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "5. delete second pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-2",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				err := client.Delete(ctx, pool.ObjectMeta.Name, meta_v1.DeleteOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:1::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "test-locator-pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "2001:db8:1:2::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "6. delete first pool",
			pool: &isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "test-locator-pool-1",
				},
			},
			poolOperation: func(ctx context.Context, pool *isovalent_api_v1alpha1.IsovalentSRv6LocatorPool, client isovalent_client_v1alpha1.IsovalentSRv6LocatorPoolInterface) error {
				err := client.Delete(ctx, pool.ObjectMeta.Name, meta_v1.DeleteOptions{})
				return err
			},
			expectedChanges: []SIDManagerEvent{
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{},
						},
					},
				},
				{
					eventType: watch.Modified,
					object: &isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{},
						},
					},
				},
			},
		},
	}

	// initialize test fixture
	f := newFixture()
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	f.hive.Start(ctx)
	defer f.hive.Stop(ctx)

	// initialize with test nodeAllocations
	for _, node := range testNodes {
		_, err := f.nodeResClient.Create(ctx, &slim_core_v1.Node{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: node,
			},
		}, meta_v1.CreateOptions{})
		req.NoError(err)
	}

	// wait for manager to synchronize
	req.Eventually(func() bool {
		return f.manager.synced
	}, maxTestDuration, time.Millisecond*100)

	// watch for SRv6SIDManagers
	watch, err := f.srv6SIDManagerClient.Watch(ctx, meta_v1.ListOptions{})
	req.NoError(err)
	defer watch.Stop()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			err := step.poolOperation(ctx, step.pool, f.locatorPoolClient)
			req.NoError(err)

			sidManagerEvents := collectEvents(req, ctx, watch.ResultChan(), len(step.expectedChanges))
			sameSIDManagers(req, poolPrefixLen, sidManagerEvents, step.expectedChanges)
		})
	}
}

type SIDManagerEvent struct {
	eventType watch.EventType
	object    *isovalent_api_v1alpha1.IsovalentSRv6SIDManager
}

// collectEvents collects events from the watch channel until either the context is done or the number of events is reached.
func collectEvents(req *require.Assertions, ctx context.Context, watchCh <-chan watch.Event, numOfEvents int) []SIDManagerEvent {
	res := make([]SIDManagerEvent, 0, numOfEvents)
	for {
		if len(res) == numOfEvents {
			return res
		}

		select {
		case <-ctx.Done():
			req.Failf("sameSIDManagers", "timeout waiting for %d events, received events %v", numOfEvents, res)
		case event, ok := <-watchCh:
			if !ok {
				req.Failf("sameSIDManagers", "unexpected closed channel")
			}
			resource, ok := event.Object.(*isovalent_api_v1alpha1.IsovalentSRv6SIDManager)
			if !ok {
				req.Failf("sameSIDManagers", "unexpected object type: %T", event.Object)
			}
			res = append(res, SIDManagerEvent{
				eventType: event.Type,
				object:    resource,
			})
		}
	}
}

// sameSIDManagers validates that the running SRv6SIDManagers match the expected SRv6SIDManagers.
func sameSIDManagers(req *require.Assertions, poolPrefixLen int, running, expected []SIDManagerEvent) {
	req.Len(running, len(expected))

	for _, expectedSIDManager := range expected {
		found := false
		for i, runningSIDManager := range running {
			if runningSIDManager.object.Name == expectedSIDManager.object.Name {
				found = true
				req.Equal(expectedSIDManager.eventType, runningSIDManager.eventType)

				cmpAllocators(req, poolPrefixLen, runningSIDManager.object.Spec.LocatorAllocations, expectedSIDManager.object.Spec.LocatorAllocations)

				// remove the found element from the running slice
				running = append(running[:i], running[i+1:]...)
				break
			}
		}
		req.True(found, "expected SID Manager %v not found", expectedSIDManager.object.Name)
	}

	// running should be empty
	req.Len(running, 0)
}

func Test_Resync(t *testing.T) {
	poolPrefixLen := 48

	tests := []struct {
		description         string
		init                initialConfig
		nodes               []string
		expectedLocators    map[string]allocations // key is node name, value is map of pool name to locator
		nondeterministic    bool                   // skip strict validation in non-deterministic tests
		expectedSIDManagers []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager
	}{
		{
			description: "internal state synced, initial locator pool and sid managers are in sync",
			nodes:       []string{"node-1", "node-2"},
			init: initialConfig{
				locatorpools: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "pool-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
							Prefix:       "fc00::/48",
							Structure:    sid_40_24_16,
							BehaviorType: "Base",
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "pool-2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
							Prefix:       "fd00::/48",
							Structure:    sid_40_24_16,
							BehaviorType: "uSID",
						},
					},
				},
				sidmanagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:10::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fd00:0:0:10::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:20::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fd00:0:0:20::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedLocators: map[string]allocations{
				"node-1": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:10::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},

					"pool-2": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fd00:0:0:10::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeUSID,
					},
				},
				"node-2": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:20::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},
					"pool-2": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fd00:0:0:20::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeUSID,
					},
				},
			},
			expectedSIDManagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:10::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
							{
								PoolRef: "pool-2",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fd00:0:0:10::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "uSID",
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:20::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
							{
								PoolRef: "pool-2",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fd00:0:0:20::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "uSID",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "extra pool in sid managers, which should be removed after resync",
			nodes:       []string{"node-1", "node-2"},
			init: initialConfig{
				locatorpools: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "pool-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
							Prefix:       "fc00::/48",
							Structure:    sid_40_24_16,
							BehaviorType: "Base",
						},
					},
				},
				sidmanagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:10::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fd00:0:0:10::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:20::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
								{
									PoolRef: "pool-2",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fd00:0:0:20::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "uSID",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedLocators: map[string]allocations{
				"node-1": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:10::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},
				},
				"node-2": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:20::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},
				},
			},
			expectedSIDManagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:10::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:20::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			description: "missing pool in sid managers, which should be added after resync",
			nodes:       []string{"node-1", "node-2"},
			init: initialConfig{
				locatorpools: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "pool-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
							Prefix:       "fc00::/48",
							Structure:    sid_40_24_16,
							BehaviorType: "Base",
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "pool-2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolSpec{
							Prefix:       "fd00::/48",
							Structure:    sid_40_24_16,
							BehaviorType: "uSID",
						},
					},
				},
				sidmanagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-1",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:10::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: "node-2",
						},
						Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
							LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
								{
									PoolRef: "pool-1",
									Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
										{
											Prefix:       "fc00:0:0:20::/64",
											Structure:    sid_40_24_16,
											BehaviorType: "Base",
										},
									},
								},
							},
						},
					},
				},
			},
			nondeterministic: true,
			expectedLocators: map[string]allocations{
				"node-1": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:10::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},

					"pool-2": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fd00:0:0:0::/64"), // bit map is non-deterministic, so we just check the prefix
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeUSID,
					},
				},
				"node-2": {
					"pool-1": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fc00:0:0:10::/64"),
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeBase,
					},

					"pool-2": &LocatorInfo{
						Locator: *types.MustNewLocator(
							netip.MustParsePrefix("fd00:0:0:0::/64"), // bit map is non-deterministic, so we just check the prefix
							types_sid_40_24_16,
						),
						BehaviorType: types.BehaviorTypeUSID,
					},
				},
			},
			expectedSIDManagers: []*isovalent_api_v1alpha1.IsovalentSRv6SIDManager{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:10::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
							{
								PoolRef: "pool-2",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fd00:0:0:0::/64", // bit map is non-deterministic, so we just check the prefix
										Structure:    sid_40_24_16,
										BehaviorType: "uSID",
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: isovalent_api_v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: "pool-1",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fc00:0:0:20::/64",
										Structure:    sid_40_24_16,
										BehaviorType: "Base",
									},
								},
							},
							{
								PoolRef: "pool-2",
								Locators: []*isovalent_api_v1alpha1.IsovalentSRv6Locator{
									{
										Prefix:       "fd00:0:0:0::/64", // bit map is non-deterministic, so we just check the prefix
										Structure:    sid_40_24_16,
										BehaviorType: "uSID",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	req := require.New(t)

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			f := newFixture()
			ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
			defer cancel()

			// initialize test nodeAllocations
			for _, node := range tt.nodes {
				_, err := f.nodeResClient.Create(ctx, &slim_core_v1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: node,
					},
				}, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			// initialize nodeAllocations and sid managers
			for _, pool := range tt.init.locatorpools {
				_, err := f.locatorPoolClient.Create(ctx, pool, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			for _, sidManager := range tt.init.sidmanagers {
				_, err := f.srv6SIDManagerClient.Create(ctx, sidManager, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			// start the controller
			f.hive.Start(ctx)
			defer f.hive.Stop(ctx)

			// wait for manager to synchronize
			req.Eventually(func() bool {
				return f.manager.synced
			}, maxTestDuration, time.Millisecond*100)

			// validate internal node state
			var runningNodes []string
			for node := range f.manager.nodeAllocations {
				runningNodes = append(runningNodes, node)
			}
			req.ElementsMatch(runningNodes, tt.nodes)

			// locators are matching
			for nodeName, nodeLocators := range tt.expectedLocators {
				runningLocators, exists := f.manager.nodeAllocations[nodeName]
				req.True(exists)
				req.Len(runningLocators, len(nodeLocators), "node %s mismatch in number of pools", nodeName)

				for poolName, expectedPoolLoc := range nodeLocators {
					runningPoolLoc, exists := runningLocators[poolName]
					req.True(exists)
					if !tt.nondeterministic {
						req.EqualValues(expectedPoolLoc, runningPoolLoc, "node %s nodeName pool %s locator mismatch", nodeName, poolName)
					}
				}
			}

			for _, nodeRef := range tt.nodes {
				nodeLocators, exists := f.manager.nodeAllocations[nodeRef]
				req.True(exists)

				req.Len(tt.init.locatorpools, len(nodeLocators), "mismatch in number of locator pools")

				for _, pool := range tt.init.locatorpools {
					_, exists := nodeLocators[pool.Name]
					req.True(exists)
				}
			}

			// validate SRv6SIDManagers
			sidManagers, err := f.srv6SIDManagerClient.List(ctx, meta_v1.ListOptions{})
			req.NoError(err)
			req.Len(sidManagers.Items, len(tt.expectedSIDManagers))

			for _, expectedSIDManager := range tt.expectedSIDManagers {
				found := false
				for _, sidManager := range sidManagers.Items {
					if sidManager.Name == expectedSIDManager.Name {
						found = true
						cmpAllocators(req, poolPrefixLen, expectedSIDManager.Spec.LocatorAllocations, sidManager.Spec.LocatorAllocations)
						break
					}
				}
				req.True(found, "expected SID Manager %v not found", expectedSIDManager.Name)
			}

			// check if there are extra SID managers created
			for _, sidManager := range sidManagers.Items {
				found := false
				for _, expectedSIDManager := range tt.expectedSIDManagers {
					if sidManager.Name == expectedSIDManager.Name {
						found = true
						break
					}
				}
				req.True(found, "unexpected SID Manager %v found", sidManager.Name)
			}
		})
	}
}

func cmpAllocators(req *require.Assertions, locPrefixLen int, i, j []*isovalent_api_v1alpha1.IsovalentSRv6LocatorAllocation) {
	type data struct {
		pool         string
		prefix       string
		sid          isovalent_api_v1alpha1.IsovalentSRv6SIDStructure
		behaviorType string
	}
	var (
		firstPools  []data
		secondPools []data
	)

	for _, p := range i {
		// compare prefix till locator pool prefix length, as node IDs are non-deterministic
		prefix := netip.MustParsePrefix(p.Locators[0].Prefix)
		shortPrefix, err := prefix.Addr().Prefix(locPrefixLen)
		req.NoError(err)

		d := data{
			pool:         p.PoolRef,
			prefix:       shortPrefix.String(),
			sid:          p.Locators[0].Structure,
			behaviorType: p.Locators[0].BehaviorType,
		}
		firstPools = append(firstPools, d)
	}

	for _, p := range j {
		// compare prefix till locator pool prefix length, as node IDs are non-deterministic
		prefix := netip.MustParsePrefix(p.Locators[0].Prefix)
		shortPrefix, err := prefix.Addr().Prefix(locPrefixLen)
		req.NoError(err)

		d := data{
			pool:         p.PoolRef,
			prefix:       shortPrefix.String(),
			sid:          p.Locators[0].Structure,
			behaviorType: p.Locators[0].BehaviorType,
		}
		secondPools = append(secondPools, d)
	}

	req.ElementsMatch(firstPools, secondPools)
}
