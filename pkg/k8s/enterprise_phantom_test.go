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

	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/service/store"

	cmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
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

func TestPhantomServiceUpdate(t *testing.T) {
	svcCache := NewCEServiceMerger(NewServiceCache(fakeDatapath.NewNodeAddressing()), cmcfg.Config{})

	svc := store.ClusterService{
		Cluster:   "other",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]store.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]store.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	}

	swg := lock.NewStoppableWaitGroup()
	id := ServiceID{Cluster: svc.Cluster, Name: svc.Name, Namespace: svc.Namespace}

	// The service is not marked as phantom, hence it should not be present in the cache.
	svc.IncludeExternal, svc.Shared = true, true
	require.False(t, isPhantomService(&svc), "The service should not be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.NotContains(t, svcCache.sc.services, id, "The service should not have been added to the cache")

	// The service is now marked as phantom, hence it should be present in the cache.
	svc.IncludeExternal, svc.Shared = false, true
	require.True(t, isPhantomService(&svc), "The service should be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.Contains(t, svcCache.sc.services, id, "The service should have been added to the cache")

	// The update event should be triggered.
	event := <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, id, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")

	// The service is again marked as non-phantom, hence it should be removed.
	svc.IncludeExternal, svc.Shared = true, true
	require.False(t, isPhantomService(&svc), "The service should not be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.NotContains(t, svcCache.sc.services, id, "The service should have been removed from the cache")

	// The deletion event should be triggered.
	event = <-svcCache.sc.Events
	require.Equal(t, DeleteService, event.Action, "Received incorrect service event")
	require.Equal(t, id, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 0, "Received incorrect service event")
}

func TestPhantomServiceDelete(t *testing.T) {
	svcCache := NewCEServiceMerger(NewServiceCache(fakeDatapath.NewNodeAddressing()), cmcfg.Config{})

	svc := store.ClusterService{
		Cluster:   "other",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]store.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]store.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	}

	swg := lock.NewStoppableWaitGroup()
	id := ServiceID{Cluster: svc.Cluster, Name: svc.Name, Namespace: svc.Namespace}

	// The service is now marked as phantom, hence it should be present in the cache.
	svc.IncludeExternal, svc.Shared = false, true
	require.True(t, isPhantomService(&svc), "The service should be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.Contains(t, svcCache.sc.services, id, "The service should have been added to the cache")

	// The update event should be triggered.
	event := <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, id, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")

	// The service is deleted, hence it should be removed.
	svcCache.MergeExternalServiceDelete(&svc, swg)
	require.NotContains(t, svcCache.sc.services, id, "The service should have been removed from the cache")

	// The deletion event should be triggered.
	event = <-svcCache.sc.Events
	require.Equal(t, DeleteService, event.Action, "Received incorrect service event")
	require.Equal(t, id, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 0, "Received incorrect service event")
}

func TestGlobalToPhantomToGlobalService(t *testing.T) {
	svcCache := NewCEServiceMerger(NewServiceCache(fakeDatapath.NewNodeAddressing()), cmcfg.Config{})

	k8sSvc := slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"service.cilium.io/global": "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "foo",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}

	svc := store.ClusterService{
		Cluster:   "other",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]store.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]store.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	}

	swg := lock.NewStoppableWaitGroup()
	globalID := ServiceID{Cluster: svc.Cluster, Name: svc.Name, Namespace: svc.Namespace}

	localID := svcCache.sc.UpdateService(&k8sSvc, swg)
	svcCache.sc.UpdateEndpoints(&Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: localID.Namespace,
			Name:      localID.Name,
		},
		EndpointSliceID: EndpointSliceID{
			ServiceID: localID,
		},
	}, swg)

	// Consume the event generated by UpdateEndpoints.
	<-svcCache.sc.Events

	// The service is not marked as phantom, hence it should not be present
	// when indexed by cluster name.
	svc.IncludeExternal, svc.Shared = true, true
	require.False(t, isPhantomService(&svc), "The service should not be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.Contains(t, svcCache.sc.services, localID, "The service should be in cache (by local ID)")
	require.NotContains(t, svcCache.sc.services, globalID, "The service should not be in cache (by global ID)")

	// The update event for the local service should be triggered, to include
	// the remote endpoints.
	event := <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, localID, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")

	// The service is now marked as phantom, hence it should be present when
	// indexed by cluster name.
	svc.IncludeExternal, svc.Shared = false, true
	require.True(t, isPhantomService(&svc), "The service should be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.Contains(t, svcCache.sc.services, localID, "The service should be in cache (by local ID)")
	require.Contains(t, svcCache.sc.services, globalID, "The service should be in cache (by global ID)")

	// The update event for the local service should be triggered, to remove
	// the remote endpoints.
	event = <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, localID, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 0, "Received incorrect service event")

	// The update event for the phantom service should be triggered.
	event = <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, globalID, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")

	// The service is not marked as phantom again, hence it should not be present
	// when indexed by cluster name.
	svc.IncludeExternal, svc.Shared = true, true
	require.False(t, isPhantomService(&svc), "The service should not be phantom")
	svcCache.MergeExternalServiceUpdate(&svc, swg)
	require.Contains(t, svcCache.sc.services, localID, "The service should be in cache (by local ID)")
	require.NotContains(t, svcCache.sc.services, globalID, "The service should not be in cache (by global ID)")

	// The delete event for the phantom service should be triggered.
	event = <-svcCache.sc.Events
	require.Equal(t, DeleteService, event.Action, "Received incorrect service event")
	require.Equal(t, globalID, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 0, "Received incorrect service event")

	// The update event for the local service should be triggered, to include
	// the remote endpoints.
	event = <-svcCache.sc.Events
	require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
	require.Equal(t, localID, event.ID, "Received incorrect service event")
	require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")
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
