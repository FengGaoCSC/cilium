// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cache

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/testflow"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
)

func TestAggregationCacheWithoutExpiration(t *testing.T) {
	// expiration may never be 0, it will default to some value
	assert.NotEqual(t, time.Duration(0), NewCache(Configuration{}).conf.Expiration)
}

func TestAggregationStateChange(t *testing.T) {
	p1 := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		FlowState:   types.FlowState{ConnectionRequest: true},
	}
	p2 := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		FlowState:   types.FlowState{ConnectionRequest: true, ACK: true},
	}

	c := NewCache(Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
	})

	clock := clockwork.NewFakeClock()
	c.clock = clock

	time1 := clock.Now().UTC()
	res := c.Aggregate(p1)
	assert.Equal(t, observer.StateChange_new, res.StateChange)
	assert.Equal(t, time1, res.AggregatedFlow.Stats.Forward.LastActivity.AsTime())
	assert.Equal(t, time1, res.AggregatedFlow.Stats.Forward.FirstActivity.AsTime())
	assert.Equal(t, uint64(1), res.AggregatedFlow.Stats.Forward.NumFlows)

	// Advance the clock, store the time for checking it later
	clock.Advance(30 * time.Second)
	time2 := clock.Now().UTC()

	res = c.Aggregate(p2)
	assert.Equal(t, observer.StateChange_unspec, res.StateChange)
	assert.Equal(t, time2, res.AggregatedFlow.Stats.Forward.LastActivity.AsTime())
	// First activity was time1, not time2
	assert.Equal(t, time1, res.AggregatedFlow.Stats.Forward.FirstActivity.AsTime())
	assert.Equal(t, uint64(2), res.AggregatedFlow.Stats.Forward.NumFlows)
}

func TestAggregationCache(t *testing.T) {
	a := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		VerdictStr:  "10",
		DropReason:  20,
	}
	b := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("f00::1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("f11::1"), Port: 22},
		VerdictStr:  "20",
		DropReason:  30,
		Reply:       true,
	}

	c := NewCache(Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
	})

	assert.Equal(t, observer.StateChange_new, c.Aggregate(a).StateChange)
	assert.Equal(t, a, c.Lookup(a).FirstFlow)
	assert.Equal(t, observer.StateChange_new|observer.StateChange_first_reply, c.Aggregate(b).StateChange)
	assert.Equal(t, b, c.Lookup(b).FirstFlow)
	// subsequent reply flows should not trigger first_reply state change.
	assert.Equal(t, observer.StateChange_unspec, c.Aggregate(b).StateChange)
}

func TestAggregationCacheExpiration(t *testing.T) {
	a := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		VerdictStr:  "10",
		DropReason:  20,
	}
	c := NewCache(Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
		Expiration:  30 * time.Second,
	})

	clock := clockwork.NewFakeClock()
	c.clock = clock

	ctx, cancel := context.WithCancel(context.Background())
	go c.StartGC(ctx)
	defer func() {
		cancel()
		assert.NoError(t, c.WaitForShutdown(context.Background()))
	}()

	assert.Equal(t, observer.StateChange_new, c.Aggregate(a).StateChange)
	assert.Equal(t, a, c.Lookup(a).FirstFlow)
	clock.Advance(time.Minute)
	assert.Nil(t, c.Lookup(a))
}
