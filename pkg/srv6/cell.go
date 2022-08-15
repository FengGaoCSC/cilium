// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"srv6-manager",
	"SRv6 DataPath Manager",

	// The Controller which is the entry point of the module
	cell.Provide(NewSRv6Manager),
)
