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

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/testflow"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"
)

func TestAggregationCacheWithoutExpiration(t *testing.T) {
	// expiration may never be 0, it will default to some value
	assert.False(t, NewCache(context.Background(), Configuration{}).conf.Expiration == time.Duration(0))
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

	ctx, cancel := context.WithCancel(context.Background())
	c := NewCache(ctx, Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
	})

	timeBeforeP1 := time.Now()
	assert.True(t, c.Aggregate(p1).StateChange == observer.StateChange_new)
	timeBeforeP2 := time.Now()
	assert.True(t, c.Aggregate(p2).StateChange == observer.StateChange_unspec)
	timeBeforeP3 := time.Now()

	af := c.Lookup(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
	})

	assert.True(t, af.Stats.Forward.NumFlows == 2)

	ts, err := ptypes.Timestamp(af.Stats.Forward.FirstActivity)
	assert.True(t, err == nil)
	assert.True(t, timeBeforeP1.Before(ts) && timeBeforeP2.After(ts))
	ts, err = ptypes.Timestamp(af.Stats.Forward.LastActivity)
	assert.True(t, err == nil)
	assert.True(t, timeBeforeP2.Before(ts) && timeBeforeP3.After(ts))
	cancel()
	assert.NoError(t, c.WaitForShutdown(context.Background()))
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

	ctx, cancel := context.WithCancel(context.Background())
	c := NewCache(ctx, Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
	})

	assert.True(t, c.Aggregate(a).StateChange == observer.StateChange_new)
	assert.True(t, c.Lookup(a).FirstFlow == a)
	assert.True(t, c.Aggregate(b).StateChange == observer.StateChange_new|observer.StateChange_first_reply)
	assert.True(t, c.Lookup(b).FirstFlow == b)
	// subsequent reply flows should not trigger first_reply state change.
	assert.True(t, c.Aggregate(b).StateChange == observer.StateChange_unspec)
	cancel()
	assert.NoError(t, c.WaitForShutdown(context.Background()))
}

func TestAggregationCacheExpiration(t *testing.T) {
	a := &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 11},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		VerdictStr:  "10",
		DropReason:  20,
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := NewCache(ctx, Configuration{
		CompareFunc: testflow.Compare,
		HashFunc:    testflow.Hash,
		Expiration:  20 * time.Millisecond,
	})

	assert.True(t, c.Aggregate(a).StateChange == observer.StateChange_new)
	assert.True(t, c.Lookup(a).FirstFlow == a)
	time.Sleep(100 * time.Millisecond)
	assert.True(t, c.Lookup(a) == nil)
	cancel()
	assert.NoError(t, c.WaitForShutdown(context.Background()))
}
