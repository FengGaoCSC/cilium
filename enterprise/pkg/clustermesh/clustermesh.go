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
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
	cectnat "github.com/cilium/cilium/enterprise/pkg/maps/ctnat"
)

type ClusterIDsManager struct {
	logger  logrus.FieldLogger
	usedIDs *clustermesh.ClusterMeshUsedIDs
	maps    cectnat.PerCluster
}

func newClusterIDManager(logger logrus.FieldLogger, maps cectnat.PerCluster) ClusterIDsManager {
	return ClusterIDsManager{
		logger:  logger,
		usedIDs: clustermesh.NewClusterMeshUsedIDs(),
		maps:    maps,
	}
}

func (mgr ClusterIDsManager) ReserveClusterID(clusterID uint32) error {
	if err := mgr.usedIDs.ReserveClusterID(clusterID); err != nil {
		return err
	}

	// ClusterID reserved. From now on, this goroutine can exclusively
	// access to the corresponding slot of per-cluster maps.
	if err := mgr.maps.Update(clusterID); err != nil {
		mgr.usedIDs.ReleaseClusterID(clusterID)
		return fmt.Errorf("unable to enforce per-cluster maps: %w", err)
	}

	return nil
}

func (mgr ClusterIDsManager) ReleaseClusterID(clusterID uint32) {
	if err := mgr.maps.Delete(clusterID); err != nil {
		mgr.logger.WithField(logfields.ClusterID, clusterID).WithError(err).
			Warning("Failed to cleanup per-cluster maps")
	}

	mgr.usedIDs.ReleaseClusterID(clusterID)
}

// cleanupStalePerClusterMaps cleanups all per-cluster (inner) maps currently
// not used by any remote clusters. This function exists for handling the case
// that users delete the remote cluster from the clustermesh configuration file
// while Cilium is stopping. This should be called after ClustersSynced().
// Otherwise, we may break the existing connection on agent restart.
func (mgr ClusterIDsManager) cleanupStalePerClusterMaps() error {
	var errs []error

	mgr.usedIDs.UsedClusterIDsMutex.Lock()
	defer mgr.usedIDs.UsedClusterIDsMutex.Unlock()

	for id := uint32(1); id <= types.ClusterIDMax; id++ {
		if _, ok := mgr.usedIDs.UsedClusterIDs[id]; !ok {
			if err := mgr.maps.Delete(id); err != nil {
				errs = append(errs, fmt.Errorf("cluster ID %d: %w", id, err))
			}
		}
	}

	return errors.Join(errs...)
}

func extraIPCacheWatcherOptsProvider(cmcfg cecmcfg.Config) clustermesh.IPCacheWatcherOptsFn {
	return func(config *types.CiliumClusterConfig) []ipcache.IWOpt {
		var opts []ipcache.IWOpt

		if config != nil && cmcfg.EnableClusterAwareAddressing {
			opts = append(opts, ipcache.WithClusterID(config.ID))
		}

		return opts
	}
}