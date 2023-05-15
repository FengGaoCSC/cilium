// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multi-network")
)

const (
	// PodNetworkKey is the annotation name used to store the pod network names
	// a pod should be attached to.
	PodNetworkKey = "network.v1alpha1.isovalent.com/pod-networks"

	defaultNetwork = "default"
)

type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "multi-network-manager has been stopped"
}

type ResourceNotFound struct {
	Resource  string
	Name      string
	Namespace string
}

func (r *ResourceNotFound) Error() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + r.Name
	}
	return fmt.Sprintf("resource %s %q not found", r.Resource, name)
}

func (r *ResourceNotFound) Is(target error) bool {
	targetErr, ok := target.(*ResourceNotFound)
	if !ok {
		return false
	}
	if r != nil && targetErr.Resource != "" {
		return r.Resource == targetErr.Resource
	}
	return true
}

type Manager struct {
	podResource k8s.LocalPodResource
	podStore    resource.Store[*slim_core_v1.Pod]

	networkResource resource.Resource[*iso_v1alpha1.IsovalentPodNetwork]
	networkStore    resource.Store[*iso_v1alpha1.IsovalentPodNetwork]
}

func (m *Manager) Start(ctx hive.HookContext) (err error) {
	m.podStore, err = m.podResource.Store(ctx)
	if err != nil {
		return err
	}

	m.networkStore, err = m.networkResource.Store(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.podStore = nil
	m.networkStore = nil
	return nil
}

func (m *Manager) GetNetworksForPod(ctx context.Context, podNamespace, podName string) (*models.NetworkAttachmentList, error) {
	if m.podStore == nil || m.networkStore == nil {
		return nil, &ManagerStoppedError{}
	}

	pod, ok, err := m.podStore.GetByKey(resource.Key{
		Name:      podName,
		Namespace: podNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup pod %q: %w", podNamespace+"/"+podName, err)
	} else if !ok {
		return nil, &ResourceNotFound{Resource: "Pod", Namespace: podNamespace, Name: podName}
	}

	networkAnnotation, hasAnnotation := pod.Annotations[PodNetworkKey]
	if !hasAnnotation {
		networkAnnotation = defaultNetwork
	}

	var attachments []*models.NetworkAttachmentElement
	for _, networkName := range strings.Split(networkAnnotation, ",") {
		network, ok, err := m.networkStore.GetByKey(resource.Key{Name: networkName})
		if err != nil {
			return nil, fmt.Errorf("failed to lookup IsovalentPodNetwork %q: %w", networkName, err)
		} else if !ok {
			return nil, &ResourceNotFound{Resource: "IsovalentPodNetwork", Name: networkName}
		}

		var routes []*models.NetworkAttachmentRoute
		for _, route := range network.Spec.Routes {
			routes = append(routes, &models.NetworkAttachmentRoute{
				Destination: string(route.Destination),
				Gateway:     string(route.Gateway),
			})
		}

		attachments = append(attachments, &models.NetworkAttachmentElement{
			Name:   swag.String(networkName),
			Routes: routes,
			Ipam: &models.NetworkAttachmentIPAMParameters{
				IpamPool: network.Spec.IPAM.Pool.Name,
			},
		})
	}

	return &models.NetworkAttachmentList{
		Attachments:  attachments,
		PodName:      podName,
		PodNamespace: podNamespace,
	}, nil
}
