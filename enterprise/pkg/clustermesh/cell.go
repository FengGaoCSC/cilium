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
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"enterprise-clustermesh",
	"ClusterMesh is the Isovalent Enterprise for Cilium multicluster implementation",

	// Override the OSS ServiceMerger, to introduce the support for enterprise features.
	cell.Invoke(clustermesh.InjectCEServiceMerger),
)
