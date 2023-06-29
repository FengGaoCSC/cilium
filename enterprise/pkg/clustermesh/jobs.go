//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

type jobParams struct {
	cell.In

	Lifecycle   hive.Lifecycle
	Logger      logrus.FieldLogger
	JobRegistry job.Registry

	Config       cecmcfg.Config
	ClusterMesh  *clustermesh.ClusterMesh
	ClusterIDMgr ClusterIDsManager
}

func registerJobs(params jobParams) {
	if params.ClusterMesh == nil {
		return
	}

	group := params.JobRegistry.NewGroup(
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "enterprise-clustermesh")),
	)
	params.Lifecycle.Append(group)

	if params.Config.EnableClusterAwareAddressing {
		group.Add(job.OneShot(
			"clustermesh-cleanup-stale-maps",
			cleanupStalePerClusterMapsJobFn(params),
			job.WithRetry(3, workqueue.DefaultControllerRateLimiter()),
		))
	}
}

func cleanupStalePerClusterMapsJobFn(params jobParams) job.OneShotFunc {
	return func(ctx context.Context) error {
		if err := params.ClusterMesh.ClustersSynced(ctx); err != nil {
			return err
		}

		params.Logger.Info("Cleaning up all stale per-cluster maps")
		if err := params.ClusterIDMgr.cleanupStalePerClusterMaps(); err != nil {
			return fmt.Errorf("failed to clean up stale per-cluster maps: %w", err)
		}

		return nil
	}
}
