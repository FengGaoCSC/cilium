//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"github.com/cilium/cilium/pkg/hive"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func IsovalentFQDNGroup(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentFQDNGroupList](cs.IsovalentV1alpha1().IsovalentFQDNGroups())
	return resource.New[*isovalent_api_v1alpha1.IsovalentFQDNGroup](lc, lw), nil
}
