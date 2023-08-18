// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package locatorpool

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"

	"github.com/spf13/pflag"
)

const (
	// srv6LocatorBoolEnabled is the name of the flag to enable the SRv6 locator pool.
	srv6LocatorBoolEnabled = "srv6-locator-pool-enabled"
)

var Cell = cell.Module(
	"locator-pool",
	"SRv6 SID locator pool manager",

	// provide locator pool
	cell.Provide(newLocPoolManager),
	cell.Config(Config{}),

	cell.ProvidePrivate(
		newLocatorPoolResource,
		newSIDManagerResource,
		newNodeResource,
	),

	// Invoke an empty function to force its construction.
	cell.Invoke(func(*LocatorPoolManager) {}),
)

// Config contains the configuration for the srv6 locator pool.
type Config struct {
	Enabled bool `mapstructure:"srv6-locator-pool-enabled"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(srv6LocatorBoolEnabled, cfg.Enabled, "Enable SRv6 locator pool in Cilium")
}

func newLocatorPoolResource(lc hive.Lifecycle, c client.Clientset, cfg Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool] {
	if !cfg.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolList](
			c.IsovalentV1alpha1().IsovalentSRv6LocatorPools(),
		), resource.WithMetric("IsovalentSRv6LocatorPool"))
}

func newSIDManagerResource(lc hive.Lifecycle, c client.Clientset, cfg Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager] {
	if !cfg.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentSRv6SIDManager](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentSRv6SIDManagerList](
			c.IsovalentV1alpha1().IsovalentSRv6SIDManagers(),
		), resource.WithMetric("IsovalentSRv6SIDManager"))
}

func newNodeResource(lc hive.Lifecycle, c client.Clientset, cfg Config) resource.Resource[*slim_core_v1.Node] {
	if !cfg.Enabled {
		return nil
	}

	return resource.New[*slim_core_v1.Node](
		lc, utils.ListerWatcherFromTyped[*slim_core_v1.NodeList](
			c.Slim().CoreV1().Nodes(),
		), resource.WithMetric("Node"))
}
