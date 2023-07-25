//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package synced

import (
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// AllIsovalentCRDResourceNames returns a list of all Isovalent CRD resource
// names.
func AllIsovalentCRDResourceNames() []string {
	result := []string{
		CRDResourceName(v1alpha1.IFGName),
	}

	if option.Config.EnableIPv4EgressGateway {
		result = append(result, CRDResourceName(v1alpha1.IFGName))
	}

	return result
}
