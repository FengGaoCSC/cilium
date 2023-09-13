// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/api/v1/models"
	k8sResource "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/nodediscovery"
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

// ManagerStoppedError is returned when a API call is being made while the manager is stopped
type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "multi-network-manager has been stopped"
}

// ResourceNotFound is returned when a Kubernetes resource
// (e.g. Pod, IsovalentPodNetwork) is not found
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

type daemonConfig interface {
	IPv4Enabled() bool
	IPv6Enabled() bool
}

// Manager is responsible for managing multi-networking. It implements the
// Cilium API stubs to provide multi-networking information to the Cilium CNI
// plugin and contains an implementation of the multi-networking-aware auto direct
// node routes logic.
type Manager struct {
	config       config
	daemonConfig daemonConfig

	controllerManager *controller.Manager

	podResource k8sResource.LocalPodResource
	podStore    resource.Store[*slim_core_v1.Pod]

	networkResource resource.Resource[*iso_v1alpha1.IsovalentPodNetwork]
	networkStore    resource.Store[*iso_v1alpha1.IsovalentPodNetwork]
}

// Start initializes the manager and starts watching the Kubernetes resources.
// Invoked by the hive framework.
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

// Stop stops the manager, meaning it can no longer serve API requests.
// Invoked by the hive framework.
func (m *Manager) Stop(ctx hive.HookContext) error {
	m.podStore = nil
	m.networkStore = nil
	return nil
}

// GetConfigurationStatus returns if multi-networking is enabled. This is used
// by the Cilium CNI plugin to determine if the multi-networking logic should
// be used during a CNI ADD request.
func (m *Manager) GetConfigurationStatus() *models.DaemonConfigurationStatusMultiNetworking {
	return &models.DaemonConfigurationStatusMultiNetworking{
		Enabled: m.config.EnableMultiNetwork,
	}
}

// GetNetworksForPod returns the networks a pod should be attached to.
// The returned list of networks contains the network name, routes, and IPAM
// pool name for each network.
//
// This function is invoked via the Cilium API from the Cilium CNI plugin during
// a CNI ADD request. It uses this information to determine which how many endpoints
// (and thereby intefaces) have to be created for the new pod.
//
// We determine attached networks to by looking at the
// network.v1alpha1.isovalent.com/pod-networks annotation on the pod. If the
// annotation is not present, we default to the "default" network. Otherwise,
// we require all to-be-attached networks to be listed in the annotation,
// including the "default" one.
//
// If the pod or requested network is not yet known, we return an error. This
// will cause the CNI ADD request to fail, but it will be retried later, at which
// point the pod and/or network should hopefully be available.
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

// StartRoutingController implements a multi-network aware version of auto-direct-node-routes.
// We currently duplicate this logic here because the routing logic in the open-source linuxNodeHandler
// is not multi-network aware, but the goal is to eventually upstream this.
// The remoteNodeRouteManager logic of the routing feature subscribes to all remote CiliumNode objects,
// correlates pod CIDRs with the remote node's secondary IP, and then installs a route for each pod CIDR.
// StartRoutingController must be called before the K8s watcher is started, as it
// otherwise misses the initial CiliumNode objects in the CiliumNodeChain.
func (m *Manager) StartRoutingController(ciliumNodeChain *subscriber.CiliumNodeChain) {
	if !m.config.MultiNetworkAutoDirectNodeRoutes || m.networkStore == nil {
		return
	}

	// remoteNodeRouteManager is responsible for managing multi-network auto direct node routes
	remoteNodes := &remoteNodeRouteManager{
		networkStore: m.networkStore,
		mutex:        lock.Mutex{},
		nodes:        make(map[string]*remoteNode),
	}

	// Collects podCIDRs from remote nodes and install routes
	ciliumNodeChain.Register(remoteNodes)

	// Regularly reinstall all routes in case networks have changed or routes have been manually removed
	m.controllerManager.UpdateController(remoteRouteController, controller.ControllerParams{
		DoFunc:      remoteNodes.resyncNodes,
		RunInterval: 1 * time.Minute,
	})
}

// StartLocalIPCollector is part of the multi-network-aware auto-direct-node-routes feature.
// The localNetworkIPCollector auto-detects the secondary node IPs of the local node (based on network routes)
// and announces them in the CiliumNode object via NodeDiscovery.
// This must be called after the CiliumNode resource has already been registered, as it invokes
// NodeDiscovery.UpdateLocalNode.
func (m *Manager) StartLocalIPCollector(nodeDiscovery *nodediscovery.NodeDiscovery) {
	if !m.config.MultiNetworkAutoDirectNodeRoutes || m.networkStore == nil {
		return
	}

	// localNetworkIPCollector auto-detects local node IPs and provides them to
	// nodeDiscovery
	localIP := &localNetworkIPCollector{
		daemonConfig:        m.daemonConfig,
		networkStore:        m.networkStore,
		mutex:               lock.Mutex{},
		nodeIPByNetworkName: make(map[string]nodeIPPair),
	}

	// Collects local podCIDRs and stores them in nodeIPByNetworkName
	m.controllerManager.UpdateController(localNodeSyncController, controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			return localIP.updateNodeIPAddresses(nodeDiscovery)
		},
		RunInterval: 15 * time.Second,
	})
	// Announces IPs in nodeIPByNetworkName in CiliumNode via NodeDiscovery
	nodeDiscovery.WithAdditionalNodeAddressSource(localIP)
}
