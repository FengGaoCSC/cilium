// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package plugins

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
)

// Init for Cilium agent plugin looks the same as the generic plugin.Init.
type Init func() (Instance, error)

// Instance for an agent plugin, after Init() was called.
type Instance interface{}

// Instances is a collection of multiple Instance objects.
type Instances []Instance

// ServerOptions allows the plugin to affect the server options. Options are
// added in the order that plugins are initialized.
type ServerOptions interface {
	ServerOptions() []observeroption.Option
}

// Flags allows plugins to add additional cilium-agent flags.
//
// If the flag is not hidden, by default a corresponding viper environment
// variable is going to be found using the standard cilium conventions.
type Flags interface {
	AddAgentFlags() *pflag.FlagSet
}

// DepAcceptor allows for a plugin to accept dependencies (other plugins).
//
// While accepting dependencies, plugin has control over the execution moving
// forward. For example, if a required dependency is missing an error can be
// returned stating as such.
type DepAcceptor interface {
	AcceptDeps(Instances) error
}
