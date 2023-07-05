// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type mockStore[T comparable] map[resource.Key]T

func (m mockStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	item, exists = m[key]
	return item, exists, nil
}

func (m mockStore[T]) Get(obj T) (item T, exists bool, err error) {
	panic("not implemented")
}

func (m mockStore[T]) List() []T {
	panic("not implemented")
}

func (m mockStore[T]) IterKeys() resource.KeyIter {
	panic("not implemented")
}

func (m mockStore[T]) CacheStore() cache.Store {
	panic("not implemented")
}

func podKey(ns, name string) resource.Key {
	return resource.Key{
		Namespace: ns,
		Name:      name,
	}
}

func networkKey(name string) resource.Key {
	return resource.Key{
		Name: name,
	}
}

func TestManager_GetNetworksForPod(t *testing.T) {
	m := &Manager{
		podStore: mockStore[*slim_core_v1.Pod]{
			podKey("default", "client"): &slim_core_v1.Pod{},
			podKey("default", "multi-homed-workload"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						PodNetworkKey: "default,jupiter",
					},
				},
			},
			podKey("default", "secondary-only-workload"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						PodNetworkKey: "jupiter",
					},
				},
			},
			podKey("default", "nonexistent-network-workload"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						PodNetworkKey: "mars",
					},
				},
			},
			podKey("default", "existent-and-nonexistent-network-workload"): &slim_core_v1.Pod{
				ObjectMeta: slim_meta_v1.ObjectMeta{
					Annotations: map[string]string{
						PodNetworkKey: "jupiter,mars",
					},
				},
			},
		},
		networkStore: mockStore[*iso_v1alpha1.IsovalentPodNetwork]{
			networkKey("default"): &iso_v1alpha1.IsovalentPodNetwork{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: defaultNetwork,
				},
				Spec: iso_v1alpha1.PodNetworkSpec{
					IPAM: iso_v1alpha1.IPAMSpec{
						Mode: "multi-pool",
						Pool: iso_v1alpha1.IPAMPoolSpec{
							Name: "default",
						},
					},
					Routes: []iso_v1alpha1.RouteSpec{},
				},
			},
			networkKey("jupiter"): &iso_v1alpha1.IsovalentPodNetwork{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "jupiter",
				},
				Spec: iso_v1alpha1.PodNetworkSpec{
					IPAM: iso_v1alpha1.IPAMSpec{
						Mode: "multi-pool",
						Pool: iso_v1alpha1.IPAMPoolSpec{
							Name: "jupiter",
						},
					},
					Routes: []iso_v1alpha1.RouteSpec{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name            string
		podNamespace    string
		podName         string
		wantAttachments []*models.NetworkAttachmentElement
		wantErr         error
	}{
		{
			name:         "no annotations",
			podNamespace: "default",
			podName:      "client",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String(defaultNetwork),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "default",
					},
				},
			},
		},
		{
			name:         "multi-homed",
			podNamespace: "default",
			podName:      "multi-homed-workload",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String(defaultNetwork),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "default",
					},
				},
				{
					Name: swag.String("jupiter"),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "jupiter",
					},
					Routes: []*models.NetworkAttachmentRoute{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
		{
			name:         "secondary only",
			podNamespace: "default",
			podName:      "secondary-only-workload",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String("jupiter"),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "jupiter",
					},
					Routes: []*models.NetworkAttachmentRoute{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
		{
			name:         "nonexistent pod",
			podNamespace: "nonesuch",
			podName:      "pod",
			wantErr:      &ResourceNotFound{Resource: "Pod"},
		},
		{
			name:         "nonexistent network",
			podNamespace: "default",
			podName:      "nonexistent-network-workload",
			wantErr:      &ResourceNotFound{Resource: "IsovalentPodNetwork"},
		},
		{
			name:         "existent and nonexistent network",
			podNamespace: "default",
			podName:      "existent-and-nonexistent-network-workload",
			wantErr:      &ResourceNotFound{Resource: "IsovalentPodNetwork"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := m.GetNetworksForPod(context.TODO(), tt.podNamespace, tt.podName)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetNetworksForPod() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if networks.PodNamespace != tt.podNamespace {
				t.Errorf("GetNetworksForPod() pod namespace = %v, want %v", networks.PodNamespace, tt.podNamespace)
			}
			if networks.PodName != tt.podName {
				t.Errorf("GetNetworksForPod() pod name = %v, want %v", networks.PodName, tt.podName)
			}
			attachments := networks.Attachments
			sort.Slice(attachments, func(i, j int) bool {
				return swag.StringValue(attachments[i].Name) < swag.StringValue(attachments[j].Name)
			})
			if diff := cmp.Diff(tt.wantAttachments, attachments); diff != "" {
				t.Errorf("GetNetworksForPod() attachments mismatch (-want +got):\n%s", diff)
			}
		})
	}

}
