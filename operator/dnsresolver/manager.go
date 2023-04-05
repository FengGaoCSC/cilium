// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/workerpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	"github.com/cilium/cilium/operator/dnsclient"
	operatormetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/metrics"
)

type mgrMetrics struct {
	// enabled enables metrics reporting from the dnsresolver cell
	enabled bool

	// fqdnResolvers is the number of background FQDN resolvers started by the DNS resolver manager.
	fqdnResolvers prometheus.Gauge

	// fqdnGroupReconcilers is the number of IsovalentFDQNGroup reconcilers started by the DNS resolver manager.
	fqdnGroupReconcilers prometheus.Gauge
}

// manager is responsible for handling IsovalentFQDNGroup events. It will spin
// up resolvers and reconcilers to handle each instance of an
// IsovalentFQDNGroup.
type manager struct {
	logger logrus.FieldLogger

	shutdowner hive.Shutdowner

	clientset cilium_client_v2alpha1.CiliumCIDRGroupInterface
	fqdnGroup resource.Resource[*v1alpha1.IsovalentFQDNGroup]

	ctrMgr *controller.Manager

	dnsClient   dnsclient.Resolver
	minInterval time.Duration

	// fqdn -> resolver
	resolvers map[string]*resolver
	// fqdnGroup -> cidr group reconciler
	reconcilers map[string]*reconciler

	// cache contains the mappings between IsovalentFQDNGroups and their FQDNs.
	cache status

	store *fqdnStore

	wp *workerpool.WorkerPool

	metrics mgrMetrics
}

func newManager(params resolverManagerParams) *manager {
	if !params.Clientset.IsEnabled() {
		return nil
	}

	mgr := &manager{
		logger:      params.Logger,
		shutdowner:  params.Shutdowner,
		clientset:   params.Clientset.CiliumV2alpha1().CiliumCIDRGroups(),
		fqdnGroup:   params.FQDNGroupResource,
		ctrMgr:      controller.NewManager(),
		dnsClient:   params.DNSClient,
		minInterval: params.Cfg.FQDNGroupMinQueryInterval,
		resolvers:   make(map[string]*resolver),
		reconcilers: make(map[string]*reconciler),
		cache:       make(status),
		store:       newStore(),
		wp:          workerpool.New(1),
	}
	mgr.metrics.enabled = params.EnableMetrics

	params.LC.Append(mgr)

	return mgr
}

func (mgr *manager) Start(hive.HookContext) error {
	mgr.logger.Info("Starting DNS resolvers manager")

	mgr.registerMetrics()

	return mgr.wp.Submit("dns-resolvers-manager", mgr.run)
}

func (mgr *manager) Stop(hive.HookContext) error {
	mgr.logger.Info("Stopping DNS resolvers manager")

	if err := mgr.wp.Close(); err != nil {
		return err
	}

	return nil
}

func (mgr *manager) registerMetrics() {
	if !mgr.metrics.enabled {
		mgr.metrics.fqdnResolvers = metrics.NoOpGauge
		mgr.metrics.fqdnGroupReconcilers = metrics.NoOpGauge
		return
	}

	mgr.metrics.fqdnResolvers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: operatormetrics.Namespace,
		Name:      "fqdn_resolvers_total",
		Help:      "Number of background FQDN resolvers started by the Operator",
	})
	mgr.metrics.fqdnGroupReconcilers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: operatormetrics.Namespace,
		Name:      "fqdngroup_reconcilers_total",
		Help:      "Number of IsovalentFQDNGroup reconcilers started by the Operator",
	})
	operatormetrics.Registry.MustRegister(mgr.metrics.fqdnResolvers)
	operatormetrics.Registry.MustRegister(mgr.metrics.fqdnGroupReconcilers)
}

func (mgr *manager) run(ctx context.Context) error {
	for event := range mgr.fqdnGroup.Events(ctx) {
		var err error
		switch event.Kind {
		case resource.Upsert:
			err = mgr.onUpdate(ctx, event.Object)
		case resource.Delete:
			err = mgr.onDelete(ctx, event.Object)
		}
		event.Done(err)
	}

	var errs []error
	for _, resolver := range mgr.resolvers {
		if err := resolver.close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, reconciler := range mgr.reconcilers {
		if err := reconciler.close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := multierr.Combine(errs...); err != nil {
		mgr.shutdowner.Shutdown(hive.ShutdownWithError(err))
	}
	mgr.ctrMgr.RemoveAllAndWait()

	return nil
}

func (mgr *manager) onUpdate(ctx context.Context, obj *v1alpha1.IsovalentFQDNGroup) error {
	var (
		action string
		err    error
	)

	// wrap the function calls into a naked func() to capture variables in the closure
	defer func() {
		if !mgr.metrics.enabled {
			return
		}

		operatormetrics.KubernetesEventProcessed.WithLabelValues(
			MetricIFG,
			action,
			result(err),
		).Inc()
		ifgEventReceived(action, err == nil)
		mgr.metrics.fqdnGroupReconcilers.Set(float64(len(mgr.reconcilers)))
	}()

	fqdnGroup := obj.Name
	if _, ok := mgr.cache[fqdnGroup]; !ok {
		action = resources.MetricCreate
	} else {
		action = resources.MetricUpdate
	}

	mgr.logger.WithField("fqdnGroup", fqdnGroup).Debug(
		"resyncing streams and restarting cidr group reconciler",
	)

	fqdns := toStrings(obj.Spec.FQDNs)
	err = mgr.syncResolvers(fqdnGroup, fqdns)
	if err != nil {
		return fmt.Errorf("failed to sync resolvers on FQDNGroup %s update: %w", fqdnGroup, err)
	}

	// stop the old reconciler and start a new one listening to notifications
	// related to the updated FQDNGroup
	if reconciler, ok := mgr.reconcilers[fqdnGroup]; ok {
		err = reconciler.close()
		if err != nil {
			return fmt.Errorf("failed to close reconciler on FQDNGroup %s update: %w", fqdnGroup, err)
		}
	}
	reconciler := newReconciler(
		mgr.logger,
		fqdnGroup,
		obj.GetUID(),
		fqdns,
		mgr.clientset,
		mgr.ctrMgr,
		mgr.store,
	)
	err = reconciler.run()
	if err != nil {
		return fmt.Errorf("failed to run reconciler on FQDNGroup %s update: %w", fqdnGroup, err)
	}

	// update internal mgr cache
	mgr.cache[fqdnGroup] = fqdns
	mgr.reconcilers[fqdnGroup] = reconciler

	return nil
}

func (mgr *manager) onDelete(ctx context.Context, obj *v1alpha1.IsovalentFQDNGroup) error {
	var err error

	// wrap the function calls into a naked func() to capture variables in the closure
	defer func() {
		if !mgr.metrics.enabled {
			return
		}

		operatormetrics.KubernetesEventProcessed.WithLabelValues(
			MetricIFG,
			resources.MetricDelete,
			result(err),
		).Inc()
		ifgEventReceived(resources.MetricDelete, err == nil)
		mgr.metrics.fqdnGroupReconcilers.Set(float64(len(mgr.reconcilers)))
	}()

	fqdnGroup := obj.Name
	mgr.logger.WithField("fqdnGroup", fqdnGroup).Debug(
		"deleting streams and cidr group reconciler",
	)

	if reconciler, ok := mgr.reconcilers[fqdnGroup]; ok {
		err = reconciler.close()
		if err != nil {
			return fmt.Errorf("failed to close reconciler on FQDNGroup %s delete: %w", fqdnGroup, err)
		}
	}

	err = mgr.ctrMgr.RemoveController(fqdnGroup)
	if err != nil {
		return fmt.Errorf("failed to remove reconciler FQDNGroup %s controller: %w", fqdnGroup, err)
	}

	err = mgr.syncResolvers(fqdnGroup, nil)
	if err != nil {
		return fmt.Errorf("failed to sync resolvers on FQDNGroup %s delete: %w", fqdnGroup, err)
	}

	// update internal mgr cache
	delete(mgr.cache, fqdnGroup)
	delete(mgr.reconcilers, fqdnGroup)

	return nil
}

func toStrings(objFQDNs []v1alpha1.FQDN) []string {
	fqdns := make([]string, 0, len(objFQDNs))
	for _, fqdn := range objFQDNs {
		fqdns = append(fqdns, string(fqdn))
	}
	return fqdns
}

func (mgr *manager) syncResolvers(fqdnGroup string, fqdns []string) error {
	defer func() { mgr.metrics.fqdnResolvers.Set(float64(len(mgr.resolvers))) }()

	newStatus := mgr.cache.deepCopy()
	newStatus[fqdnGroup] = fqdns

	newFQDNs, staleFQDNs := mgr.cache.diff(newStatus)

	// start a reconciler for each new fqdn to resolve
	mgr.logger.WithFields(logrus.Fields{
		"fqdnGroup":    fqdnGroup,
		"newResolvers": newFQDNs,
	}).Debug("starting new fqdn resolvers after FQDNGroup event")

	for _, fqdn := range newFQDNs {
		resolver := newResolver(mgr.logger, fqdn, fqdnGroup, mgr.dnsClient, mgr.minInterval, mgr.store)
		if err := resolver.run(); err != nil {
			return fmt.Errorf("failed to start resolver for %s: %w", fqdn, err)
		}
		mgr.resolvers[fqdn] = resolver
	}

	// stop any stale resolver
	if len(staleFQDNs) > 0 {
		mgr.logger.WithFields(logrus.Fields{
			"fqdnGroup":      fqdnGroup,
			"staleResolvers": staleFQDNs,
		}).Debug("stopping stale fqdn resolvers after FQDNGroup event")
	}

	for _, fqdn := range staleFQDNs {
		resolver, ok := mgr.resolvers[fqdn]
		if !ok {
			return fmt.Errorf("fqdn resolver for %s not found", fqdn)
		}
		if err := resolver.close(); err != nil {
			return fmt.Errorf("failed to close resolver for %s: %w", fqdn, err)
		}
		delete(mgr.resolvers, fqdn)
	}

	return nil
}

func ifgEventReceived(action string, valid bool) {
	operatormetrics.EventTS.WithLabelValues(
		operatormetrics.LabelEventSourceK8s,
		MetricIFG,
		action,
	).SetToCurrentTime()
	operatormetrics.KubernetesEventReceived.WithLabelValues(
		MetricIFG,
		action,
		strconv.FormatBool(valid),
		strconv.FormatBool(false),
	).Inc()
}

func result(err error) string {
	if err == nil {
		return "success"
	} else {
		return "failed"
	}
}
