// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package multinetwork

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"multinetwork-operator",
	"Operator cell for the multi-network feature",

	cell.Invoke(newMultiNetworkOperator),
	cell.Config(defaultConfig),
)

var defaultConfig = config{
	EnableMultiNetwork:          false,
	AutoCreateDefaultPodNetwork: true,
}

type config struct {
	EnableMultiNetwork          bool
	AutoCreateDefaultPodNetwork bool
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-multi-network", c.EnableMultiNetwork, "Enable support for multiple pod networks") // same as cilium-agent
	flags.Bool("auto-create-default-pod-network", c.AutoCreateDefaultPodNetwork, "Automatically creates the default IsovalentPodNetwork on startup")
}
