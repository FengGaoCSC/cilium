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
	"testing"

	"github.com/cilium/cilium-cli/connectivity/check"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestExternalCiliumDNSProxySource(t *testing.T) {
	ciliumDNSProxyPod := check.Pod{
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: ExternalCiliumDNSProxyName,
						Args: []string{"--expose-metrics", "--prometheus-port=99675"},
					},
				},
			},
		},
	}

	podWithPrometheusMissing := check.Pod{
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: ExternalCiliumDNSProxyName,
						Args: []string{"--expose-metrics"},
					},
				},
			},
		},
	}

	tests := map[string]struct {
		dnsProxyPods map[string]check.Pod
		want         check.MetricsSource
	}{
		"nominal case": {
			dnsProxyPods: map[string]check.Pod{
				"cilium-dnsproxy-lm2xk": ciliumDNSProxyPod,
			},
			want: check.MetricsSource{
				Name: ExternalCiliumDNSProxyName,
				Pods: []check.Pod{ciliumDNSProxyPod},
				Port: "99675",
			},
		},
		"with two pods": {
			dnsProxyPods: map[string]check.Pod{
				"cilium-dnsproxy-lm2xk": podWithPrometheusMissing,
				"cilium-dnsproxy-t5j79": ciliumDNSProxyPod,
			},
			want: check.MetricsSource{
				Name: ExternalCiliumDNSProxyName,
				Pods: []check.Pod{podWithPrometheusMissing, ciliumDNSProxyPod},
				Port: "99675",
			},
		},
		"no cilium dns proxy pods": {
			dnsProxyPods: map[string]check.Pod{},
			want:         check.MetricsSource{},
		},
		"no prometheus container port": {
			dnsProxyPods: map[string]check.Pod{ExternalCiliumDNSProxyName: podWithPrometheusMissing},
			want:         check.MetricsSource{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ExternalCiliumDNSProxySource(tc.dnsProxyPods)
			assert.Equal(t, tc.want, got)
		})
	}
}
