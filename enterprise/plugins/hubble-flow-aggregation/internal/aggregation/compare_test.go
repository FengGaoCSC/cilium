// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregation

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/cache"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/testflow"

	"github.com/stretchr/testify/assert"
)

var (
	a = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		VerdictStr:  "10",
		DropReason:  20,
	}
	b = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("f00::1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("f11::1"), Port: 22},
		ProtocolStr: "TCP",
		VerdictStr:  "20",
		DropReason:  30,
	}
)

func TestAggregatorCache(t *testing.T) {
	ca := NewAggregator(context.Background(), cache.Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
	})

	assert.True(t, ca.String() == Name)

	assert.True(t, ca.Aggregate(a).StateChange == observer.StateChange_new)
	assert.True(t, ca.Aggregate(a).StateChange == observer.StateChange_unspec)
	assert.True(t, ca.Aggregate(a).StateChange == observer.StateChange_unspec)
	assert.True(t, ca.Cache().Lookup(a) != nil)
	assert.True(t, ca.Cache().Lookup(b) == nil)

	assert.True(t, ca.Aggregate(b).StateChange == observer.StateChange_new)
	assert.True(t, ca.Aggregate(b).StateChange == observer.StateChange_unspec)
	assert.True(t, ca.Aggregate(b).StateChange == observer.StateChange_unspec)
	assert.True(t, ca.Cache().Lookup(b) != nil)
	assert.True(t, ca.Cache().Lookup(a) != nil)
}
