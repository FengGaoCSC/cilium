//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package deploy

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// MustGetEchoPodOtherNode returns the representation of the "echo-other-node"
// pod running in the cluster, or call ct.Fatal if not found.
func MustGetEchoPodOtherNode(ct *check.ConnectivityTest) check.Pod {
	for _, po := range ct.EchoPods() {
		if po.HasLabel("name", "echo-other-node") {
			return po
		}
	}

	ct.Fatal("Failed to retrieve information about the echo-other-node pod")
	return check.Pod{Pod: &corev1.Pod{}}
}
