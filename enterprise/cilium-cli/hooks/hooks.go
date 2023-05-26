// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"github.com/cilium/cilium-cli/cli"
	"github.com/cilium/cilium-cli/connectivity/check"
)

// EnterpriseHooks implements cli.Hooks interface to add connectivity tests and
// sysdump tasks that are specific to Isovalent Enterprise for Cilium.
type EnterpriseHooks struct {
	cli.NopHooks
}

// AddConnectivityTests implements cli.Hooks
func (eh *EnterpriseHooks) AddConnectivityTests(ct *check.ConnectivityTest) error {
	return addConnectivityTests(ct)
}
