//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package maps

import (
	"github.com/cilium/cilium/pkg/hive/cell"

	cectnat "github.com/cilium/cilium/enterprise/pkg/maps/ctnat"
)

var Cell = cell.Module(
	"enterprise-maps",
	"Isovalent Enterprise for Cilium BPF Maps",

	// CT and NAT per-cluster maps.
	cectnat.Cell,
)
