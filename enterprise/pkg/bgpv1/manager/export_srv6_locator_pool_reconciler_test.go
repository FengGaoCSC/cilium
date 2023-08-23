//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

type fakeSIDManager struct {
	Allocators map[string]sidmanager.SIDAllocator
}

func (fsm *fakeSIDManager) ManageSID(poolName string, fn func(allocator sidmanager.SIDAllocator) (bool, error)) error {
	_, err := fn(fsm.Allocators[poolName])
	if err != nil {
		return err
	}
	return nil
}

func (fsm *fakeSIDManager) Subscribe(subscriberName string, subscriber sidmanager.SIDManagerSubscriber, done func()) {
	return
}

func TestExportSRv6LocatorPoolReconciler(t *testing.T) {
	locator1 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:1::/48"),
		srv6Types.MustNewSIDStructure(32, 16, 16, 0),
	)
	locator2 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:2::/48"),
		srv6Types.MustNewSIDStructure(32, 16, 16, 0),
	)
	locator3 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:3::/48"),
		srv6Types.MustNewSIDStructure(32, 16, 16, 0),
	)

	tests := []struct {
		name                 string
		selector             *slim_metav1.LabelSelector
		initLocators         map[string]*srv6Types.Locator
		initResources        []v1alpha1.IsovalentSRv6LocatorPool
		initAdvertiments     []*types.Path
		expectedAdvertiments sets.Set[string]
	}{
		{
			name: "Single Pool Create",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			initAdvertiments: []*types.Path{},
			expectedAdvertiments: sets.New[string](
				locator1.Prefix.String(),
			),
		},
		{
			name: "Single Pool Locator Change",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator2,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
			},
			expectedAdvertiments: sets.New[string](
				locator2.Prefix.String(),
			),
		},
		{
			name: "Single Pool Label Change",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
			},
			expectedAdvertiments: sets.New[string](),
		},
		{
			name: "Single Pool Delete",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators:  map[string]*srv6Types.Locator{},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
			},
			expectedAdvertiments: sets.New[string](),
		},
		{
			name: "Multi Pool Create",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator2,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			initAdvertiments: []*types.Path{},
			expectedAdvertiments: sets.New[string](
				locator1.Prefix.String(),
				locator2.Prefix.String(),
			),
		},
		{
			name: "Multi Pool Locator Change",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator3,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
				types.NewPathForPrefix(locator2.Prefix),
			},
			expectedAdvertiments: sets.New[string](
				locator1.Prefix.String(),
				locator3.Prefix.String(),
			),
		},
		{
			name: "Multi Pool Label Change",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator2,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
				types.NewPathForPrefix(locator2.Prefix),
			},
			expectedAdvertiments: sets.New[string](
				locator1.Prefix.String(),
			),
		},
		{
			name: "Multi Pool Delete",
			selector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"export": "true",
				},
			},
			initLocators: map[string]*srv6Types.Locator{
				"pool1": locator1,
			},
			initResources: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			initAdvertiments: []*types.Path{
				types.NewPathForPrefix(locator1.Prefix),
				types.NewPathForPrefix(locator2.Prefix),
			},
			expectedAdvertiments: sets.New[string](
				locator1.Prefix.String(),
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSC, err := manager.NewServerWithConfig(
				context.TODO(),
				types.ServerParameters{
					Global: types.BGPGlobal{
						ASN:        65000,
						RouterID:   "10.0.0.1",
						ListenPort: -1,
					},
				},
			)
			require.NoError(t, err)

			testSC.SRv6LocatorAnnouncements = test.initAdvertiments

			fsm := &fakeSIDManager{
				Allocators: make(map[string]sidmanager.SIDAllocator),
			}

			for poolName, l := range test.initLocators {
				sa, err := sidmanager.NewStructuredSIDAllocator(l, srv6Types.BehaviorTypeBase)
				require.NoError(t, err)
				fsm.Allocators[poolName] = sa
			}

			fc, cs := k8sclient.NewFakeClientset()

			for _, r := range test.initResources {
				fc.CiliumFakeClientset.Tracker().Create(
					v1alpha1.SchemeGroupVersion.WithResource("isovalentsrv6locatorpools"),
					r.DeepCopy(), "",
				)
			}

			rsc := newIsovalentSRv6LocatorPoolResource(hivetest.Lifecycle(t), cs, &option.DaemonConfig{EnableBGPControlPlane: true, EnableSRv6: true})
			store, err := rsc.Store(context.TODO())
			require.NoError(t, err)

			logger := logging.DefaultLogger
			logger.SetLevel(logrus.DebugLevel)

			reconciler := ExportLocatorPoolReconciler{
				logger:           logger,
				sidManager:       fsm,
				locatorPoolStore: store,
			}
			reconciler.initialized.Store(true)

			params := manager.ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: &v2alpha1.CiliumBGPVirtualRouter{
					SRv6LocatorPoolSelector: test.selector,
				},
			}

			require.NoError(t, reconciler.Reconcile(context.TODO(), params))

			advertisements := sets.New[string]()
			for _, p := range params.CurrentServer.SRv6LocatorAnnouncements {
				require.IsType(t, &bgp.IPv6AddrPrefix{}, p.NLRI)
				advertisements.Insert(p.NLRI.(*bgp.IPv6AddrPrefix).String())
			}

			require.True(t, advertisements.Equal(test.expectedAdvertiments), advertisements.SymmetricDifference(test.expectedAdvertiments))
		})
	}
}
