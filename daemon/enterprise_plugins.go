// nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"log"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/plugins"
	aggregation "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation"
	export "github.com/cilium/cilium/enterprise/plugins/hubble-flow-export"
	policymetadata "github.com/cilium/cilium/enterprise/plugins/hubble-flow-policy-metadata"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var pluginInits = []plugins.Init{
	policymetadata.New, // must come before export
	aggregation.New,
	export.New,
}

func init() {
	list, err := Initialize(pluginInits)
	if err != nil {
		log.Fatalf("failed to initialize plugins: %v", err)
	}

	if err := AddFlags(cmd.Vp, cmd.RootCmd, list); err != nil {
		log.Fatalf("unable to apply cilium CLI options: %v", err)
	}

	if err := AddServerOptions(list); err != nil {
		log.Fatalf("unable to add server options: %v", err)
	}
}

// Initialize a list of plugins from their initializers.
func Initialize(inits []plugins.Init) (plugins.Instances, error) {
	var res plugins.Instances

	for _, i := range inits {
		inst, err := i()
		if err != nil {
			return nil, fmt.Errorf("failed to call plugin init: %w", err)
		}
		res = append(res, inst)
	}

	return res, nil
}

// AddFlags to the root cilium-agent command.
func AddFlags(vp *viper.Viper, root *cobra.Command, list plugins.Instances) error {
	for _, i := range list {
		if adder, ok := i.(plugins.Flags); ok {
			fs := adder.AddAgentFlags()

			// iterate over all the flags, and add them to the actual root
			// command set.
			fs.VisitAll(func(f *pflag.Flag) {
				root.Flags().AddFlag(f)

				if !f.Hidden {
					option.BindEnv(vp, f.Name)
				}

				// Pick up the setting from viper if it's set.
				if vp.IsSet(f.Name) && vp.GetString(f.Name) != "" {
					if err := root.Flags().Set(f.Name, vp.GetString(f.Name)); err != nil {
						log.Fatalf("failed to set %s from viper: %s", f.Name, err)
					}
				}
			})
		}
	}

	// re-bind pflags to viper after all the plugins had a go
	if err := vp.BindPFlags(root.Flags()); err != nil {
		return fmt.Errorf("failed to bind pflags to viper: %v", err)
	}

	return nil
}

// AddServerOptions includes all the options from the list of plugins.
func AddServerOptions(list plugins.Instances) error {
	for _, i := range list {
		if so, ok := i.(plugins.ServerOptions); ok {
			observer.DefaultOptions = append(
				observer.DefaultOptions,
				so.ServerOptions()...,
			)
		}
	}

	return nil
}
