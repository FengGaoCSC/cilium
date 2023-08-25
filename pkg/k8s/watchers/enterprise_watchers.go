//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package watchers

import (
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/pkg/lock"
)

// EgressGatewayHAmanager is the manager for the egress gateway HA feature. This
// is a temporary hack to export the enterprise manager to the k8s watchers
// (endpoint and nodes) until the manager starts using the Resource[T] mechanism
// to subscribe to the relevant k8s resources.
var EgressGatewayHAManagerLock lock.RWMutex
var EgressGatewayHAManager *egressgatewayha.Manager
