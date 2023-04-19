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
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

var Cell = cell.Module(
	"enterprise-clustermesh",
	"ClusterMesh is the Isovalent Enterprise for Cilium multicluster implementation",

	cell.Config(cecmcfg.Config{}),

	cell.Provide(
		// Strictly require that the cluster-config is always exposed by
		// remote clusters when overlapping PodCIDR support is enabled.
		func(cfg cecmcfg.Config) cmtypes.ValidationMode {
			return cmtypes.ValidationMode(cfg.EnableClusterAwareAddressing)
		},

		// Inject the ClusterIDManager implementation with the extended logic
		// to handle per-cluster maps creation and removal.
		newClusterIDManager,
		func(mgr ClusterIDsManager) clustermesh.ClusterIDsManager { return mgr },

		// Inject the extra datapath configs required for overlapping PodCIDR support.
		datapathNodeHeaderConfigProvider,
	),

	cell.Invoke(
		// Override the OSS ServiceMerger, to introduce the support for enterprise features.
		clustermesh.InjectCEServiceMerger,

		// Validate the enterprise clustermesh configuration.
		func(cfg cecmcfg.Config, dcfg *option.DaemonConfig) error {
			return cfg.Validate(dcfg)
		},

		// Register enterprise-only jobs, currently handling the garbage
		// collection of stale per-cluster maps.
		registerJobs,
	),
)
