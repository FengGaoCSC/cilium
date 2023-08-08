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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestPhantomServiceMutator(t *testing.T) {
	tests := []struct {
		name     string
		svc      slim_corev1.Service
		expected Service
	}{
		{
			name: "Phantom service",
			svc: slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Annotations: map[string]string{"service.isovalent.com/phantom": "true"},
				},
				Spec: slim_corev1.ServiceSpec{
					ClusterIP: "127.0.0.1",
					Type:      slim_corev1.ServiceTypeLoadBalancer,
				},
				Status: slim_corev1.ServiceStatus{
					LoadBalancer: slim_corev1.LoadBalancerStatus{
						Ingress: []slim_corev1.LoadBalancerIngress{
							{IP: "192.168.0.1"},
							{IP: "192.168.0.3"},
						},
					},
				},
			},
			expected: Service{
				Shared:      true,
				FrontendIPs: []net.IP{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.3")},
			},
		},
		{
			name: "Non-phantom service",
			svc: slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Annotations: map[string]string{"service.isovalent.com/phantom": "false"},
				},
			},
			expected: Service{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input Service
			PhantomServiceMutator(&tt.svc, &input)
			require.Equal(t, tt.expected, input)
		})
	}
}

func TestGetAnnotationPhantom(t *testing.T) {
	tests := []struct {
		name            string
		annotations     map[string]string
		svcType         slim_corev1.ServiceType
		expectedGlobal  bool
		expectedShared  bool
		expectedPhantom bool
	}{
		{
			name:    "LoadBalancer service without annotations",
			svcType: slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:        "ClusterIP service, phantom annotation set",
			annotations: map[string]string{"service.isovalent.com/phantom": "true"},
			svcType:     slim_corev1.ServiceTypeClusterIP,
		},
		{
			name:        "LoadBalancer service, phantom annotation not set",
			annotations: map[string]string{"service.isovalent.com/phantom": "false"},
			svcType:     slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:            "LoadBalancer service, phantom annotation set (lowercase)",
			annotations:     map[string]string{"service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true,
		},
		{
			name:            "LoadBalancer service, phantom annotation set (uppercase)",
			annotations:     map[string]string{"service.isovalent.com/phantom": "TRUE"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true,
		},
		{
			name:           "LoadBalancer service, both global and phantom annotations set",
			annotations:    map[string]string{"service.cilium.io/global": "true", "service.isovalent.com/phantom": "true"},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: true, // A global service is shared by default if not otherwise specified.
		},
		{
			name:           "LoadBalancer service, global annotation set, phantom annotation unset",
			annotations:    map[string]string{"service.cilium.io/global": "true", "service.isovalent.com/phantom": "false"},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true,
			expectedShared: true,
		},
		{
			name:        "LoadBalancer service, shared annotation set, phantom annotation unset",
			annotations: map[string]string{"service.cilium.io/shared": "true", "service.isovalent.com/phantom": "false"},
			svcType:     slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:            "LoadBalancer service, both shared and phantom annotations set",
			annotations:     map[string]string{"service.cilium.io/shared": "true", "service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true, // The shared service annotation does not affect the phantom service one.
		},
		{
			name:            "LoadBalancer service, shared annotation unset, phantom annotation set",
			annotations:     map[string]string{"service.cilium.io/shared": "false", "service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true, // The shared service annotation does not affect the phantom service one.
		},
		{
			name: "LoadBalancer service, global + shared + phantom annotations set",
			annotations: map[string]string{
				"service.cilium.io/global":      "true",
				"service.cilium.io/shared":      "true",
				"service.isovalent.com/phantom": "true",
			},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: true,
		},
		{
			name: "LoadBalancer service, global annotation set, shared annotation unset, phantom annotation set",
			annotations: map[string]string{
				"service.cilium.io/global":      "true",
				"service.cilium.io/shared":      "false",
				"service.isovalent.com/phantom": "true",
			},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{Annotations: tt.annotations},
				Spec:       slim_corev1.ServiceSpec{Type: tt.svcType},
			}

			assert.Equal(t, tt.expectedGlobal, getAnnotationIncludeExternal(&svc), "Incorrect global service detection")
			assert.Equal(t, tt.expectedShared, getAnnotationShared(&svc), "Incorrect shared service detection")
			assert.Equal(t, tt.expectedPhantom, getAnnotationPhantom(&svc), "Incorrect phantom service detection")
		})
	}
}
