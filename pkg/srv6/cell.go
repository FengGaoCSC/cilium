// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
)

var Cell = cell.Module(
	"srv6-manager",
	"SRv6 DataPath Manager",

	// The Controller which is the entry point of the module
	cell.Provide(NewSRv6Manager),

	// Provides access to events and read-only store of CiliumEndpoint resources
	cell.Provide(k8s.CiliumSlimEndpointResource),
)
