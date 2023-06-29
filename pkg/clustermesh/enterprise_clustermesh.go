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
	"github.com/cilium/cilium/pkg/k8s"

	cmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

// InjectCEServiceMerger allows to override the default ServiceMerger injected
// through hive, to support additional enterprise features in addition to global
// services (e.g., phantom services). This method is intended to be executed
// through an Invoke function before starting the clustermesh subsystem.
func InjectCEServiceMerger(cm *ClusterMesh, cmcfg cmcfg.Config, sc *k8s.ServiceCache) {
	if cm != nil {
		cm.conf.ServiceMerger = k8s.NewCEServiceMerger(sc, cmcfg)
	}
}
