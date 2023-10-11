//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/deploy"
)

func PodToPhantomService() check.Scenario {
	return &podToPhantomService{}
}

type podToPhantomService struct{}

func (s *podToPhantomService) Name() string {
	return "pod-to-phantom-service"
}

func (s *podToPhantomService) Run(ctx context.Context, t *check.Test) {
	var (
		i int

		ct  = t.Context()
		dst = deploy.MustGetEchoPodOtherNode(ct) // Used for flow validation
	)

	for _, pod := range ct.ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		t.ForEachIPFamily(func(ipFam features.IPFamily) {
			target := check.HTTPEndpoint(fmt.Sprintf("phantom-service-%s", ipFam),
				fmt.Sprintf("http://%s:%d", deploy.PhantomServiceAddress(ipFam), deploy.PhantomServicePort))

			t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &pod, target, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(target, ipFam))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: false, AltDstIP: dst.Address(ipFam), AltDstPort: dst.Port()}))
				a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
					DNSRequired: false, AltDstIP: dst.Address(ipFam), AltDstPort: dst.Port()}))
			})
		})

		i++
	}
}
