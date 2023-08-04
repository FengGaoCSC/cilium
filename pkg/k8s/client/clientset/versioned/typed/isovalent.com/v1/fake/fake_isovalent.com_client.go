// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeIsovalentV1 struct {
	*testing.Fake
}

func (c *FakeIsovalentV1) IsovalentEgressGatewayPolicies() v1.IsovalentEgressGatewayPolicyInterface {
	return &FakeIsovalentEgressGatewayPolicies{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeIsovalentV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}