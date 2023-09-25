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
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	enterpriseK8s "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/k8s"
)

type EnterpriseConnectivityTest struct {
	*check.ConnectivityTest

	// Clients for source and destination clusters.
	clients *deploymentClients
}

func NewEnterpriseConnectivityTest(ct *check.ConnectivityTest) *EnterpriseConnectivityTest {
	client, _ := enterpriseK8s.NewEnterpriseClient(ct.K8sClient())

	c := &deploymentClients{
		src: client,
		dst: client,
	}

	return &EnterpriseConnectivityTest{
		ConnectivityTest: ct,
		clients:          c,
	}
}

func (ect *EnterpriseConnectivityTest) NewEnterpriseTest(name string) *EnterpriseTest {
	ct := ect.ConnectivityTest.NewTest(name)
	et := EnterpriseTest{
		Test:  ct,
		ctx:   ect,
		iegps: make(map[string]*isovalentv1.IsovalentEgressGatewayPolicy),
	}

	ct.WithSetupFunc(func(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
		return et.setup(ctx)
	})

	return &et
}
