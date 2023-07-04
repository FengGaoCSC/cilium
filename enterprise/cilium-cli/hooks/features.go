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
	"context"
	"fmt"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/tests"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const FeatureCiliumDNSProxyDeployed check.Feature = "cilium-dnsproxy-deployed"

func detectFeatures(ctx context.Context, ct *check.ConnectivityTest) error {
	for range ct.CiliumPods() {
		err := extractExternalDNSProxyFeature(ctx, ct)
		if err != nil {
			return fmt.Errorf("failed to extract feature %s", FeatureCiliumDNSProxyDeployed)
		}
	}

	return nil
}

func extractExternalDNSProxyFeature(ctx context.Context, ct *check.ConnectivityTest) error {
	isDeployed, err := detectExternalCiliumDNSProxyFeature(ctx, ct)
	if err != nil {
		return err
	}

	ct.Features[FeatureCiliumDNSProxyDeployed] = check.FeatureStatus{
		Enabled: isDeployed,
	}

	return nil
}

// detectExternalCiliumDNSProxyFeature returns true if cilium-dnsproxy pods are deployed.
func detectExternalCiliumDNSProxyFeature(ctx context.Context, ct *check.ConnectivityTest) (bool, error) {
	// Check if pods are deployed.
	for range ct.Clients() {
		// cilium-dnsproxy pods are labelled with `k8s-app=ciliumdns-proxy`, let's filter on it.
		ciliumDNSProxyLabelSelector := fmt.Sprintf("k8s-app=%s", tests.ExternalCiliumDNSProxyName)
		pods, err := ct.K8sClient().ListPods(ctx, "kube-system", metav1.ListOptions{LabelSelector: ciliumDNSProxyLabelSelector})
		if err != nil {
			return false, fmt.Errorf("unable to list %s pods: %w", tests.ExternalCiliumDNSProxyName, err)
		}

		if len(pods.Items) == 0 {
			return false, nil
		}
	}

	// Check if configmap is set to enable external dns proxy.
	cm, err := ct.K8sClient().GetConfigMap(ctx, "kube-system", defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return false, fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	if v, ok := cm.Data["external-dns-proxy"]; !ok || v != "true" {
		return false, nil
	}

	return true, nil
}
