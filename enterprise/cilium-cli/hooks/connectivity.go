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
