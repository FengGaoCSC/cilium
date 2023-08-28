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
	"runtime/pprof"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

var (
	// eventsOpts are the options used with resource's Events()
	eventsOpts = resource.WithRateLimiter(
		// This rate limiter will retry in the following pattern
		// 250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 32s, .... max 5m
		workqueue.NewItemExponentialFailureRateLimiter(250*time.Millisecond, 5*time.Minute),
	)
)

type LocatorPoolManagerParams struct {
	cell.In

	Cfg Config

	Logger      logrus.FieldLogger
	LC          hive.Lifecycle
	JobRegistry job.Registry

	Clientset k8sClient.Clientset

	SRv6SIDManagerResource resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager]
	LocatorPoolResource    resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool]
	NodeResource           resource.Resource[*slim_core_v1.Node]
}

// allocations is a map of locator pools, key is pool name and value is locator allocated from this pool
type allocations map[string]*LocatorInfo

// LocatorPoolManager is responsible for managing SRv6 Locator Pools
type LocatorPoolManager struct {
	cfg    Config
	logger logrus.FieldLogger

	// resource to be modified
	srv6SIDManagerClient isovalent_client_v1alpha1.IsovalentSRv6SIDManagerInterface

	// resources to watch
	srv6SIDManagerResource resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager]
	locPoolResource        resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool]
	nodeResource           resource.Resource[*slim_core_v1.Node]

	// internal state
	synced bool

	pools           map[string]LocatorPool
	nodeAllocations map[string]allocations

	nodeEvents <-chan resource.Event[*slim_core_v1.Node]
	poolEvents <-chan resource.Event[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool]
}

func newLocPoolManager(p LocatorPoolManagerParams) (*LocatorPoolManager, error) {
	p.Logger.Info("SRv6 Locator LocatorPool new manager")

	if !p.Cfg.Enabled {
		return nil, nil
	}

	jobGroup := p.JobRegistry.NewGroup(
		job.WithLogger(p.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "locatorpool")),
	)
	lpm := &LocatorPoolManager{
		cfg:                    p.Cfg,
		logger:                 p.Logger,
		srv6SIDManagerClient:   p.Clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers(),
		srv6SIDManagerResource: p.SRv6SIDManagerResource,
		locPoolResource:        p.LocatorPoolResource,
		nodeResource:           p.NodeResource,
		pools:                  make(map[string]LocatorPool),
		nodeAllocations:        make(map[string]allocations),
	}

	jobGroup.Add(
		job.OneShot("locatorpool main", func(ctx context.Context) error {
			lpm.Run(ctx)
			return nil
		}),
	)

	p.LC.Append(jobGroup)

	return lpm, nil
}

func (lpm *LocatorPoolManager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lpm.logger.Info("Initializing")
	defer lpm.logger.Info("Shutting down")

	lpm.nodeEvents = lpm.nodeResource.Events(ctx, eventsOpts)
	lpm.poolEvents = lpm.locPoolResource.Events(ctx, eventsOpts)

	lpm.resync(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-lpm.poolEvents:
			if !ok {
				lpm.logger.Info("locator pool channel closed")
				return
			}
			lpm.handlePoolEvent(ctx, event)

		case event, ok := <-lpm.nodeEvents:
			if !ok {
				lpm.logger.Info("node resource channel closed")
				return
			}
			lpm.handleNodeEvent(ctx, event)
		}
	}
}
