// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connectivity

import (
	"fmt"

	"github.com/cilium/cilium-cli/cli"
	"github.com/cilium/cilium-cli/connectivity/check"

	"github.com/isovalent/cilium/enterprise/cilium-cli/connectivity/tests"
)

const (
	testNoPolicies = "no-policies"
)

// EnterpriseHooks implements cli.Hooks interface to add connectivity tests and
// sysdump tasks that are specific to Isovalent Enterprise for Cilium.
type EnterpriseHooks struct {
	cli.NopHooks
}

// AddConnectivityTests implements cli.Hooks
func (eh *EnterpriseHooks) AddConnectivityTests(ct *check.ConnectivityTest) error {
	if err := eh.addHubbleVersionTests(ct); err != nil {
		return err
	}
	return nil
}

func (eh *EnterpriseHooks) addHubbleVersionTests(ct *check.ConnectivityTest) error {
	test, err := ct.GetTest(testNoPolicies)
	if err != nil {
		return fmt.Errorf("failed to get test %s: %w", testNoPolicies, err)
	}
	test.WithScenarios(tests.HubbleCLIVersion())
	return nil
}
