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

import "github.com/cilium/cilium/pkg/k8s"

func init() {
	// Enable the special processing to support phantom services.
	K8sSvcCache.ServiceMutators = append(K8sSvcCache.ServiceMutators, k8s.PhantomServiceMutator)
}
