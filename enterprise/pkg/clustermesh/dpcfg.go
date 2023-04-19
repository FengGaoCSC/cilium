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

	"github.com/cilium/cilium/pkg/byteorder"
	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

func datapathNodeHeaderConfigProvider(cfg cecmcfg.Config, dcfg *option.DaemonConfig, localNode *node.LocalNodeStore) dpcfgdef.NodeFnOut {
	return dpcfgdef.NewNodeFnOut(func() (dpcfgdef.Map, error) {
		output := make(dpcfgdef.Map)

		if cfg.EnableClusterAwareAddressing {
			output["CLUSTER_ID"] = fmt.Sprintf("%d", dcfg.ClusterID)
			output["ENABLE_CLUSTER_AWARE_ADDRESSING"] = "1"
		}

		if cfg.EnableInterClusterSNAT {
			output["ENABLE_INTER_CLUSTER_SNAT"] = "1"
			if dcfg.EnableIPv4 {
				// The header configuration is executed by the daemon start hook, and
				// at that point we are guaranteed that the local node has already
				// been initialized, and this Get() operation returns immediately.
				// This is equivalent to what would have happened with node.GetIPv4().
				lno, err := localNode.Get(context.Background())
				if err != nil {
					return nil, fmt.Errorf("retrieve node info: %w", err)
				}

				output["IPV4_INTER_CLUSTER_SNAT"] = fmt.Sprintf("%#08x", byteorder.NetIPv4ToHost32(lno.GetNodeIP(false)))
			}
		}

		return output, nil
	})
}
