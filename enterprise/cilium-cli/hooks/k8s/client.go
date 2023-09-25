//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Register all auth providers (azure, gcp, oidc, openstack, ..).

	"github.com/cilium/cilium-cli/k8s"

	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	enterpriseCiliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
)

type EnterpriseClient struct {
	*k8s.Client

	EnterpriseCiliumClientset enterpriseCiliumClientset.Interface
}

func NewEnterpriseClient(client *k8s.Client) (*EnterpriseClient, error) {
	// Register the Cilium types in the default scheme.
	_ = isovalentv1.AddToScheme(scheme.Scheme)

	rawKubeConfigLoader := client.RESTClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	enterpriseCiliumClientset, err := enterpriseCiliumClientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &EnterpriseClient{
		Client:                    client,
		EnterpriseCiliumClientset: enterpriseCiliumClientset,
	}, nil
}

func (c *EnterpriseClient) ListIsovalentEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*isovalentv1.IsovalentEgressGatewayPolicyList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().List(ctx, opts)
}

func (c *EnterpriseClient) GetIsovalentEgressGatewayPolicy(ctx context.Context, name string, opts metav1.GetOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateIsovalentEgressGatewayPolicy(ctx context.Context, cegp *isovalentv1.IsovalentEgressGatewayPolicy, opts metav1.CreateOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Create(ctx, cegp, opts)
}

func (c *EnterpriseClient) UpdateIsovalentEgressGatewayPolicy(ctx context.Context, cegp *isovalentv1.IsovalentEgressGatewayPolicy, opts metav1.UpdateOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Update(ctx, cegp, opts)
}

func (c *EnterpriseClient) DeleteIsovalentEgressGatewayPolicy(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Delete(ctx, name, opts)
}
