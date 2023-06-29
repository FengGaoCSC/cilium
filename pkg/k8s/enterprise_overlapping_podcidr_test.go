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
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	cmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

func TestMergeExternalServiceUpdateClusterAware(t *testing.T) {
	tests := []struct {
		name     string
		cmcfg    cmcfg.Config
		expected cmtypes.AddrCluster
	}{
		{
			name:     "cluster-aware-addressing disabled",
			expected: cmtypes.MustParseAddrCluster("3.3.3.3"),
		},
		{
			name:     "cluster-aware-addressing enabled",
			cmcfg:    cmcfg.Config{EnableClusterAwareAddressing: true},
			expected: cmtypes.MustParseAddrCluster("3.3.3.3@11"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcMerger := NewCEServiceMerger(NewServiceCache(fakeDatapath.NewNodeAddressing()), tt.cmcfg)

			k8sSvc := slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Namespace: "bar",
					Name:      "foo",
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

			svc := serviceStore.ClusterService{
				Cluster:   "other",
				ClusterID: 11,
				Namespace: "bar",
				Name:      "foo",
				Frontends: map[string]serviceStore.PortConfiguration{
					"1.1.1.1": {},
				},
				Backends: map[string]serviceStore.PortConfiguration{
					"3.3.3.3": map[string]*loadbalancer.L4Addr{
						"port": {Protocol: loadbalancer.TCP, Port: 80},
					},
				},
				Shared:          true,
				IncludeExternal: true,
			}

			swg := lock.NewStoppableWaitGroup()
			id := svcMerger.sc.UpdateService(&k8sSvc, swg)

			svcMerger.MergeExternalServiceUpdate(&svc, swg)

			// The update event should be triggered.
			event := <-svcMerger.sc.Events
			require.Equal(t, UpdateService, event.Action, "Received incorrect service event")
			require.Equal(t, id, event.ID, "Received incorrect service event")
			require.Len(t, event.Endpoints.Backends, 1, "Received incorrect service event")
			require.Contains(t, event.Endpoints.Backends, tt.expected, "Received incorrect service event")
		})
	}
}

func TestAnnotateBackendsWithID(t *testing.T) {
	port1 := serviceStore.PortConfiguration{"foo": &loadbalancer.L4Addr{}}
	port2 := serviceStore.PortConfiguration{"bar": &loadbalancer.L4Addr{}}
	svc := serviceStore.ClusterService{
		ClusterID: 11,
		Backends: map[string]serviceStore.PortConfiguration{
			"10.1.1.1": port1, "10.1.1.2": port2,
		},
	}

	original := svc.DeepCopy()
	obtained := annotateBackendsWithID(svc)

	require.Equal(t, original, &svc, "The original object should not have been mutated")
	require.Contains(t, obtained.Backends, "10.1.1.1@11")
	require.Contains(t, obtained.Backends, "10.1.1.2@11")
	require.Equal(t, port1, obtained.Backends["10.1.1.1@11"])
	require.Equal(t, port2, obtained.Backends["10.1.1.2@11"])
}
