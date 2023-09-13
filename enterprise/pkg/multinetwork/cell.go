// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"multinetwork-manager",
	"Determines which pod network a pod attaches to",

	cell.ProvidePrivate(isovalentPodNetworkResource),
	cell.Provide(newMultiNetworkManager),
	cell.Config(defaultConfig),
)

var defaultConfig = config{
	EnableMultiNetwork:               false,
	MultiNetworkAutoDirectNodeRoutes: true,
}

type config struct {
	EnableMultiNetwork               bool
	MultiNetworkAutoDirectNodeRoutes bool
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-multi-network", c.EnableMultiNetwork, "Enable support for multiple pod networks")
	flags.Bool("multi-network-auto-direct-node-routes", c.MultiNetworkAutoDirectNodeRoutes, "Enable multi-network aware automatic L2 routing between nodes (experimental)")
}

// isovalentPodNetworkResource returns a resource handle for IsovalentPodNetworks
// Note: Ideally, his would live in github.com/cilium/cilium/daemon/k8s
// But to keep merge conflicts with Cilium OSS to a minimum, and since we are
// the only user of this resource anyway, we keep this private for now.
func isovalentPodNetworkResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentPodNetwork], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentPodNetworkList](cs.IsovalentV1alpha1().IsovalentPodNetworks()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentPodNetwork](lc, lw, resource.WithMetric("IsovalentPodNetwork")), nil
}

type managerParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Config    config

	DaemonConfig    *option.DaemonConfig
	PodResource     k8s.LocalPodResource
	NetworkResource resource.Resource[*iso_v1alpha1.IsovalentPodNetwork]
}

func newMultiNetworkManager(params managerParams) *Manager {
	if !params.Config.EnableMultiNetwork {
		return nil
	}

	manager := &Manager{
		config:       params.Config,
		daemonConfig: params.DaemonConfig,

		controllerManager: controller.NewManager(),

		podResource:     params.PodResource,
		networkResource: params.NetworkResource,
	}
	params.Lifecycle.Append(manager)

	return manager
}
