// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/tests"
)

const (
	testNoPolicies = "no-policies"
)

func addConnectivityTests(ct *check.ConnectivityTest) error {
	if err := addHubbleVersionTests(ct); err != nil {
		return err
	}
	return nil
}

func addHubbleVersionTests(ct *check.ConnectivityTest) error {
	test, err := ct.GetTest(testNoPolicies)
	if err != nil {
		return fmt.Errorf("failed to get test %s: %w", testNoPolicies, err)
	}
	test.WithScenarios(tests.HubbleCLIVersion())
	return nil
}
