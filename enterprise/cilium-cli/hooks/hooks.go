//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	"github.com/cilium/cilium-cli/cli"
	"github.com/cilium/cilium-cli/connectivity/check"

	"github.com/cilium/cilium-cli/sysdump"
)

// EnterpriseHooks implements cli.Hooks interface to add connectivity tests and
// sysdump tasks that are specific to Isovalent Enterprise for Cilium.
type EnterpriseHooks struct {
	cli.NopHooks
}

// AddConnectivityTests registers connectivity tests that are specific to
// Isovalent Enterprise for Cilium.
func (eh *EnterpriseHooks) AddConnectivityTests(ct *check.ConnectivityTest) error {
	return addConnectivityTests(ct)
}

// AddSysdumpTasks registers sysdump tasks that are specific to Isovalent
// Enterprise for Cilium.
func (eh *EnterpriseHooks) AddSysdumpTasks(collector *sysdump.Collector) error {
	return addSysdumpTasks(collector)
}
