//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import (
	"github.com/cilium/cilium/pkg/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1"
	cecm "github.com/cilium/cilium/enterprise/pkg/clustermesh"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	cemaps "github.com/cilium/cilium/enterprise/pkg/maps"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
)

var (
	EnterpriseAgent = cell.Module(
		"enterprise-agent",
		"Cilium Agent Enterprise",

		Agent,

		// enterprise-only cells here
		EnterpriseControlPlane,
		EnterpriseDatapath,
	)

	EnterpriseControlPlane = cell.Module(
		"enterprise-controlplane",
		"Control Plane Enterprise",

		cecm.Cell,
		sidmanager.SIDManagerCell,
		bgpv1.Cell,
		egressgatewayha.Cell,
		healthcheck.Cell,
	)

	EnterpriseDatapath = cell.Module(
		"enterprise-datapath",
		"Datapath Enterprise",

		cemaps.Cell,
		egressmapha.Cell,
	)
)
