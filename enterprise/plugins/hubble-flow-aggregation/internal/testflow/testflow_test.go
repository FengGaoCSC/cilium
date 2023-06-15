// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testflow

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"

	"github.com/stretchr/testify/assert"
)

var (
	a = &Flow{
		Source: Peer{
			Identity: []byte("foo"),
			IP:       net.ParseIP("1.1.1.1"),
			Port:     11,
		},
		Destination: Peer{
			Identity: []byte("bar"),
			IP:       net.ParseIP("2.2.2.2"),
			Port:     22,
		},
		VerdictStr: "10",
		DropReason: 20,
		FlowState: types.FlowState{
			ConnectionRequest: true,
		},
	}
	b = &Flow{
		Source: Peer{
			IP:   net.ParseIP("f00::1"),
			Port: 11,
		},
		Destination: Peer{
			IP:   net.ParseIP("f11::1"),
			Port: 22,
		},
		VerdictStr: "20",
		DropReason: 30,
		Reply:      true,
		FlowState: types.FlowState{
			Error: true,
		},
	}
)

func TestFieldAccess(t *testing.T) {
	assert.True(t, bytes.Equal(a.L3(types.AddrTypeIP).Source(), a.Source.IP))
	assert.True(t, bytes.Equal(a.L3(types.AddrTypeIdentity).Source(), a.Source.Identity))
	assert.True(t, bytes.Equal(a.L3(types.AddrTypeIP).Destination(), a.Destination.IP))
	assert.True(t, bytes.Equal(a.L3(types.AddrTypeIdentity).Destination(), a.Destination.Identity))
	assert.True(t, a.L4().SourcePort() == a.Source.Port)
	assert.True(t, a.L4().DestinationPort() == a.Destination.Port)
	assert.True(t, a.Verdict() == a.VerdictStr)
	assert.True(t, a.DropReasonInt() == a.DropReason)
	assert.False(t, a.IsReply())
	assert.True(t, b.IsReply())
	assert.True(t, a.State().ConnectionRequest)
	assert.False(t, a.State().Error)
	assert.False(t, b.State().ConnectionRequest)
	assert.True(t, b.State().Error)
}

func TestCompare(t *testing.T) {
	assert.True(t, a.Compare(a))
	assert.False(t, a.Compare(b))

	assert.True(t, Compare(a, a))
	assert.False(t, Compare(a, b))

	//Comparing against a non-compatible type fails
	assert.False(t, Compare(a, &FlowEmbed{}))
	assert.False(t, Compare(&FlowEmbed{Flow: &Flow{}}, b))
}

func TestHash(t *testing.T) {
	//Different flows must result in different hashes
	assert.False(t, Hash(a) == Hash(b))

	//Invalid type returns 0 hash
	assert.True(t, Hash(&FlowEmbed{Flow: &Flow{}}) == 0)
}

func TestComparePeer(t *testing.T) {
	pa1 := Peer{IP: net.ParseIP("1.1.1.1"), Port: 10}
	pa2 := Peer{IP: net.ParseIP("1.1.1.1"), Port: 10}
	pb := Peer{IP: net.ParseIP("2.2.2.2"), Port: 10}
	pc := Peer{IP: net.ParseIP("1.1.1.1"), Port: 20}

	assert.True(t, pa1.Compare(pa2))
	assert.False(t, pa1.Compare(pb))
	assert.False(t, pa1.Compare(pc))
	assert.False(t, pb.Compare(pc))
}
