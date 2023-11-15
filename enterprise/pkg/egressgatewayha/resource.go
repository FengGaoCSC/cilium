//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

// PolicyCell provides [Policy] for consumption with hive.
var PolicyCell = cell.Module(
	"egressgatewayha-policy",
	"The Egress Gateway Policy declares the desired EGW configuration",
	cell.Provide(newPolicyResource),
)

type Policy = v1.IsovalentEgressGatewayPolicy

func newPolicyResource(lc hive.Lifecycle, c client.Clientset) resource.Resource[*Policy] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped[*v1.IsovalentEgressGatewayPolicyList](c.IsovalentV1().IsovalentEgressGatewayPolicies())
	return resource.New[*Policy](lc, lw)
}
