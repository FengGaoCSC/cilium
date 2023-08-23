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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium-cli/sysdump"
)

const (
	enterpriseLabelSelector      = "app.kubernetes.io/name=hubble-enterprise"
	enterpriseAgentContainerName = "enterprise"
	enterpriseBugtoolPrefix      = "hubble-enterprise-bugtool"
	enterpriseCLICommand         = "hubble-enterprise"
)

func addSysdumpTasks(collector *sysdump.Collector) error {
	collector.AddTasks([]sysdump.Task{
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-enterprise' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-enterprise' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get 'hubble-enterprise' pods")
				}
				if err = collector.SubmitTetragonBugtoolTasks(sysdump.FilterPods(p, collector.NodeList),
					enterpriseAgentContainerName, enterpriseBugtoolPrefix, enterpriseCLICommand); err != nil {
					return fmt.Errorf("failed to collect bugtool output from 'hubble-enterprise' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-timescape' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "app.kubernetes.io/instance=hubble-timescape",
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-timescape' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-timescape' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-ui' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "app.kubernetes.io/instance=hubble-ui",
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-ui' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-ui' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'cilium-dnsproxy' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'cilium-dnsproxy' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'cilium-dnsproxy' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting DNS Proxy Daemonset",
			Quick:           false,
			Task: func(ctx context.Context) error {
				daemonSets, err := collector.Client.ListDaemonSet(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium DNS Daemonset")
				}
				if err := collector.WriteYAML("cilium-enterprise-dns-proxy-daemonset-<ts>.yaml", daemonSets); err != nil {
					return fmt.Errorf("failed to collect DNS Proxy Daemonset: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Auth Configmap",
			Quick:           false,
			Task: func(ctx context.Context) error {
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, "oauth2-proxy", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Auth Configmap")
				}
				if err := collector.WriteYAML("hubble-enterprise-oauth-configmap-<ts>.yaml", configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Enterprise Oauth Configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Configmap",
			Quick:           false,
			Task: func(ctx context.Context) error {
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, "hubble-enterprise-config", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Enterprise configmap")
				}
				if err := collector.WriteYAML("hubble-enterprise-configmap-<ts>.yaml", configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Enterprise configmap: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium SRV6 Egress Policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				srv6EgressPolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumsrv6egresspolicies",
					Version:  "v2alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, srv6EgressPolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium SRV6 Egress Policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-srv6egresspolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium SRV6 Egress Policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium SRV6 VRFs",
			Quick:       true,
			Task: func(ctx context.Context) error {
				srv6VRFs := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumsrv6vrfs",
					Version:  "v2alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, srv6VRFs, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium SRV6 VRFs: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-srv6vrfs-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium SRV6 VRFs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6SIDManager",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sidManagers := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6sidmanager",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sidManagers, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6sidmanagers-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentPodNetworks",
			Quick:       true,
			Task: func(ctx context.Context) error {
				podNetworks := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentpodnetworks",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, podNetworks, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentpodnetworks-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6LocatorPool",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6locatorpool",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6locatorpools-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				return nil
			},
		},
	})

	return nil
}
