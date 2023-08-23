// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmapha

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"egressmhaaps",
	"Egresshamaps provide access to the egress gateway HA datapath maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createPolicyMapFromDaemonConfig),
	cell.Provide(createCtMapFromDaemonConfig),
)
