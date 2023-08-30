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
	"fmt"
	"runtime/pprof"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var ExportSRv6LocatorPoolReconcilerCell = cell.Module(
	exportSRv6LocatorPoolReconcilerName,
	"BGP Control Plane Reconciler to export SRv6 locator prefix",

	cell.Provide(
		NewExportSRv6LocatorPoolReconciler,
		newIsovalentSRv6LocatorPoolResource,
	),
)

const (
	// This fits into the Hive/Cell's Module name length limit (30 chars)
	exportSRv6LocatorPoolReconcilerName = "export-srv6-locpool-reconciler"

	logFieldLocatorPool      = "locatorPool"
	logFieldLocatorPrefix    = "locatorPrefix"
	logFieldOldLocatorPrefix = "oldLocatorPrefix"
	logFieldNewLocatorPrefix = "newLocatorPrefix"
)

type exportSRv6LocatorPoolReconcilerOut struct {
	cell.Out

	Reconciler manager.ConfigReconciler `group:"bgp-config-reconciler"`
}

type exportSRv6LocatorPoolReconcilerParams struct {
	cell.In

	Lifecycle           hive.Lifecycle
	SIDManagerPromise   promise.Promise[sidmanager.SIDManager]
	LocatorPoolResource resource.Resource[*v1alpha1.IsovalentSRv6LocatorPool]
	JobRegistry         job.Registry
	Logger              logrus.FieldLogger
	Signaler            *signaler.BGPCPSignaler
	DaemonConfig        *option.DaemonConfig
}

type ExportLocatorPoolReconciler struct {
	initialized      atomic.Bool
	logger           logrus.FieldLogger
	sidManager       sidmanager.SIDManager
	locatorPoolStore resource.Store[*v1alpha1.IsovalentSRv6LocatorPool]
}

// sidManagerWatcher implements SIDManagerSubscriber interface and simply
// signals BGP CPlane when it gets add/update/delete locator events.
type sidManagerWatcher struct {
	logger   logrus.FieldLogger
	signaler *signaler.BGPCPSignaler
}

func (s *sidManagerWatcher) OnAddLocator(pool string, allocator sidmanager.SIDAllocator) {
	s.logger.WithFields(logrus.Fields{
		logFieldLocatorPool:   pool,
		logFieldLocatorPrefix: allocator.Locator().Prefix.String(),
	}).Debug("Locator added. Triggering reconciliation.")
	s.signaler.Event(struct{}{})
}

func (s *sidManagerWatcher) OnUpdateLocator(pool string, oldAllocator, newAllocator sidmanager.SIDAllocator) {
	s.logger.WithFields(logrus.Fields{
		logFieldLocatorPool:      pool,
		logFieldOldLocatorPrefix: oldAllocator.Locator().Prefix.String(),
		logFieldNewLocatorPrefix: newAllocator.Locator().Prefix.String(),
	}).Debug("Locator updated. Triggering reconciliation.")
	if oldAllocator.Locator().Prefix != newAllocator.Locator().Prefix {
		s.signaler.Event(struct{}{})
	}
}

func (s *sidManagerWatcher) OnDeleteLocator(pool string, allocator sidmanager.SIDAllocator) {
	s.logger.WithFields(logrus.Fields{
		logFieldLocatorPool:   pool,
		logFieldLocatorPrefix: allocator.Locator().Prefix.String(),
	}).Debug("Locator deleted. Triggering reconciliation.")
	s.signaler.Event(struct{}{})
}

func NewExportSRv6LocatorPoolReconciler(params exportSRv6LocatorPoolReconcilerParams) exportSRv6LocatorPoolReconcilerOut {
	if !params.DaemonConfig.BGPControlPlaneEnabled() || !params.DaemonConfig.EnableSRv6 {
		return exportSRv6LocatorPoolReconcilerOut{}
	}

	r := &ExportLocatorPoolReconciler{
		logger: params.Logger,
	}

	jobGroup := params.JobRegistry.NewGroup(
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", exportSRv6LocatorPoolReconcilerName)),
	)

	jobGroup.Add(
		job.OneShot("initializer", func(ctx context.Context) error {
			// Wait for the initial sync of SIDManager
			sm, err := params.SIDManagerPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to resolve SIDManager promise: %w", err)
			}
			r.sidManager = sm

			sm.Subscribe(exportSRv6LocatorPoolReconcilerName, &sidManagerWatcher{
				logger:   params.Logger,
				signaler: params.Signaler,
			})

			// Wait for the initial sync of locator pool store
			lps, err := params.LocatorPoolResource.Store(ctx)
			if err != nil {
				return fmt.Errorf("failed to obtain IsovalentSRv6LocatorPool store: %w", err)
			}
			r.locatorPoolStore = lps

			// Now we can start reconciliation
			r.initialized.Store(true)

			// We may have some reconciliation missed during initialization
			params.Signaler.Event(struct{}{})

			return nil
		}),
	)

	params.Lifecycle.Append(jobGroup)

	return exportSRv6LocatorPoolReconcilerOut{
		Reconciler: r,
	}
}

func (r *ExportLocatorPoolReconciler) Priority() int {
	return 40
}

func (r *ExportLocatorPoolReconciler) Reconcile(ctx context.Context, p manager.ReconcileParams) error {
	if !r.initialized.Load() {
		// Still waiting for some dependencies to initialized. Skip this reconciliation.
		r.logger.Debug("Initialization is not done. Skipping reconciliation.")
		return nil
	}

	toAdvertise := []*types.Path{}
	if p.DesiredConfig.SRv6LocatorPoolSelector != nil {
		selector, err := slim_metav1.LabelSelectorAsSelector(p.DesiredConfig.SRv6LocatorPoolSelector)
		if err != nil {
			return err
		}
		for _, lp := range r.locatorPoolStore.List() {
			var localLocator *srv6Types.Locator

			if !selector.Matches(labels.Set(lp.Labels)) {
				continue
			}

			// The pool is selected. Call SIDManager to obtain local locator prefix.
			err := r.sidManager.ManageSID(lp.Name, func(allocator sidmanager.SIDAllocator) (bool, error) {
				localLocator = allocator.Locator()
				return false, nil
			})
			if err != nil {
				return err
			}

			toAdvertise = append(toAdvertise, types.NewPathForPrefix(localLocator.Prefix))
		}
	}

	advertisements, err := manager.ExportAdvertisementsReconciler(&manager.AdvertisementsReconcilerParams{
		Ctx:                   ctx,
		Name:                  "SRv6 locator",
		Component:             "manager.exportLocatorPoolReconciler",
		Enabled:               p.DesiredConfig.SRv6LocatorPoolSelector != nil,
		SC:                    p.CurrentServer,
		NewC:                  p.DesiredConfig,
		CurrentAdvertisements: p.CurrentServer.SRv6LocatorAnnouncements,
		ToAdvertise:           toAdvertise,
	})
	if err != nil {
		return err
	}

	p.CurrentServer.SRv6LocatorAnnouncements = advertisements

	return nil
}

func newIsovalentSRv6LocatorPoolResource(lc hive.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v1alpha1.IsovalentSRv6LocatorPool] {
	if !dc.BGPControlPlaneEnabled() || !dc.EnableSRv6 || !c.IsEnabled() {
		return nil
	}
	return resource.New[*v1alpha1.IsovalentSRv6LocatorPool](
		lc, utils.ListerWatcherFromTyped[*v1alpha1.IsovalentSRv6LocatorPoolList](
			c.IsovalentV1alpha1().IsovalentSRv6LocatorPools(),
		), resource.WithMetric("IsovalentSRv6LocatorPool"))
}
