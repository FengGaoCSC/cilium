// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/srv6"
)

// VPNv4Advertisement is a container object which associates a VRF information
// and VPNv4 Prefixes
//
// The Path field is the advertised path object which can be forwarded to BGP
// server's WithdrawPath method, making withdrawing an advertised route simple.
type VPNv4Advertisement struct {
	VRF   *srv6.VRF
	Paths []*types.Path
}
