//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package linux

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

// InjectCEPrefixClusterMutator allows to inject a custom prefix cluster mutator which
// enriches the given cluster with the cluster ID of the node, if cluster aware
// addressing is enabled, and the node belongs to a remote cluster.
func InjectCEPrefixClusterMutator(dp datapath.Datapath, cmcfg cecmcfg.Config, dcfg *option.DaemonConfig) {
	if !cmcfg.EnableClusterAwareAddressing {
		return
	}

	ldp, ok := dp.(*linuxDatapath)
	if !ok {
		return
	}

	ldp.node.SetPrefixClusterMutatorFn(func(node *types.Node) []cmtypes.PrefixClusterOpts {
		var opts []cmtypes.PrefixClusterOpts
		if node.ClusterID != dcfg.ClusterID {
			opts = append(opts, cmtypes.WithClusterID(node.ClusterID))
		}
		return opts
	})
}
