// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/operator/dnsclient"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

const (
	// FQDNGroupMinQueryInterval is the minimum interval between two
	// consecutive queries for resolving a FQDN belonging to an IFG.
	FQDNGroupMinQueryInterval = "fqdn-group-min-query-interval"
)

// Cell invokes the creation of the DNS resolvers manager. The manager reacts
// to the IsovalentFQDNGroup resource events, starting or stopping DNS
// resolvers to lookup the FQDNs listed in the custom resources.
var Cell = cell.Module(
	"dns-resolver",
	"Isovalent DNS resolvers manager",

	cell.Config(defaultConfig),
	cell.Invoke(newManager),
)

// Config contains the configuration for the identity-gc.
type Config struct {
	FQDNGroupMinQueryInterval time.Duration
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(FQDNGroupMinQueryInterval, def.FQDNGroupMinQueryInterval, "Minimum interval between two consecutive queries when resolving a FQDN belonging to an IsovalentFQDNGroup")
}

var defaultConfig = Config{
	FQDNGroupMinQueryInterval: time.Minute,
}

// resolverManagerParams contains all the dependencies for the DNS resolvers manager.
// They will be provided through dependency injection.
type resolverManagerParams struct {
	cell.In

	Logger logrus.FieldLogger

	LC         hive.Lifecycle
	Shutdowner hive.Shutdowner

	Cfg               Config
	DNSClient         dnsclient.Resolver
	Clientset         k8sClient.Clientset
	FQDNGroupResource resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup]
}
