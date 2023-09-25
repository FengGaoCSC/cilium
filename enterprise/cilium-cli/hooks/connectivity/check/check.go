//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	enterpriseK8s "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/k8s"
)

type deploymentClients struct {
	src *enterpriseK8s.EnterpriseClient
	dst *enterpriseK8s.EnterpriseClient
}

func (d *deploymentClients) clients() []*enterpriseK8s.EnterpriseClient {
	if d.src != d.dst {
		return []*enterpriseK8s.EnterpriseClient{d.src, d.dst}
	}
	return []*enterpriseK8s.EnterpriseClient{d.src}
}
