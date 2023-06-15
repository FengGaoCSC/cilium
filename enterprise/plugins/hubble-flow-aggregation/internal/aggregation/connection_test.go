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
	"time"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/testflow"

	"github.com/stretchr/testify/assert"
)

var (
	p1 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		FlowState: types.FlowState{
			ConnectionRequest: true,
		},
	}
	p2 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		ProtocolStr: "TCP",
		Reply:       true,
		FlowState: types.FlowState{
			ConnectionRequest: true,
			ACK:               true,
		},
	}
	p3 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		FlowState:   types.FlowState{ACK: true},
	}
	p4 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		ProtocolStr: "TCP",
		Reply:       true,
		FlowState:   types.FlowState{ACK: true},
	}
	// Different flow
	p5a = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("3.3.3.3"), Port: 2222},
		Destination: testflow.Peer{IP: net.ParseIP("4.4.4.4"), Port: 1000},
		ProtocolStr: "TCP",
	}
	// Different flow
	p5b = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("4.4.4.4"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("3.3.3.3"), Port: 2222},
		ProtocolStr: "TCP",
		Reply:       true,
	}
	// Same IPs, different destination port
	p5c = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 2000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
	}
	// Same flow as p4 but different verdict
	p6 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		ProtocolStr: "TCP",
		VerdictStr:  "2",
		Reply:       true,
		FlowState:   types.FlowState{ACK: true},
	}
	// Closing p1/p2
	p7 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "TCP",
		FlowState: types.FlowState{
			CloseRequest: true,
			ACK:          true,
		},
	}
	p8 = &testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		ProtocolStr: "TCP",
		Reply:       true,
		FlowState: types.FlowState{
			CloseRequest: true,
			ACK:          true,
		},
	}
)

func TestConnectionHash(t *testing.T) {
	h1 := newConnectionAggregation(p1, false).Hash()
	h2 := newConnectionAggregation(p2, false).Hash()
	assert.True(t, h1 == h2)
}

func TestConnectionAggregationTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ca := NewConnectionAggregator(10*time.Second, false, true)
	go ca.Start(ctx)
	defer cancel()
	r := ca.Aggregate(p1)
	assert.True(t, r.StateChange == observer.StateChange_new)
	assert.False(t, r.AggregatedFlow.Stats.Forward.AckSeen)
	r = ca.Aggregate(p2)
	assert.True(t, r.StateChange == observer.StateChange_first_reply)
	assert.True(t, r.Reply)
	assert.True(t, r.AggregatedFlow.FirstFlow == p1)
	assert.True(t, r.AggregatedFlow.Stats.Reply.AckSeen)

	r = ca.Aggregate(p3)
	assert.True(t, r.StateChange == observer.StateChange_established)
	assert.True(t, r.AggregatedFlow.FirstFlow == p1)
	assert.True(t, r.AggregatedFlow.Stats.Forward.AckSeen)
	r = ca.Aggregate(p4)
	assert.True(t, r.StateChange == observer.StateChange_unspec)
	assert.True(t, r.AggregatedFlow.FirstFlow == p1)

	// Different flow
	r = ca.Aggregate(p5a)
	assert.True(t, r.StateChange == observer.StateChange_new)
	r = ca.Aggregate(p5b)
	assert.True(t, r.StateChange == observer.StateChange_first_reply)
	assert.True(t, r.Reply)
	r = ca.Aggregate(p5c)
	assert.True(t, r.StateChange == observer.StateChange_new)

	// Different flow
	r = ca.Aggregate(p6)
	assert.True(t, r.StateChange == observer.StateChange_new|observer.StateChange_first_reply)

	r = ca.Aggregate(p7)
	assert.True(t, r.StateChange == observer.StateChange_unspec)
	assert.True(t, r.AggregatedFlow.FirstFlow == p1)
	r = ca.Aggregate(p8)
	assert.True(t, r.StateChange == observer.StateChange_closed)
	assert.True(t, r.AggregatedFlow.FirstFlow == p1)

	af := ca.Cache().Lookup(p2)
	assert.True(t, af.FirstFlow == p1)

	assert.True(t, af.Stats.Forward.NumFlows == 3)
	assert.True(t, af.Stats.Reply.NumFlows == 3)
	assert.True(t, af.Stats.Reply.CloseRequests == 1)
}

func TestConnectionAggregationReply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ca := NewConnectionAggregator(10*time.Second, false, true)
	go ca.Start(ctx)
	defer cancel()
	r := ca.Aggregate(p2)
	assert.True(t, r.StateChange == observer.StateChange_new|observer.StateChange_first_reply)
	assert.True(t, r.Reply)
	r = ca.Aggregate(p1)
	assert.True(t, r.StateChange == observer.StateChange_unspec)
	assert.True(t, r.AggregatedFlow.FirstFlow == p2)

	r = ca.Aggregate(p4)
	assert.True(t, r.StateChange == observer.StateChange_unspec)
	assert.True(t, r.AggregatedFlow.FirstFlow == p2)
	r = ca.Aggregate(p3)
	assert.True(t, r.StateChange == observer.StateChange_established)
	assert.True(t, r.AggregatedFlow.FirstFlow == p2)

	// Different flow
	r = ca.Aggregate(p5a)
	assert.True(t, r.StateChange == observer.StateChange_new)
	r = ca.Aggregate(p5b)
	assert.True(t, r.StateChange == observer.StateChange_first_reply)
	assert.True(t, r.Reply)
	r = ca.Aggregate(p5c)
	assert.True(t, r.StateChange == observer.StateChange_new)

	// Different flow
	r = ca.Aggregate(p6)
	assert.True(t, r.StateChange == observer.StateChange_new|observer.StateChange_first_reply)

	r = ca.Aggregate(p8)
	assert.True(t, r.StateChange == observer.StateChange_unspec)
	assert.True(t, r.AggregatedFlow.FirstFlow == p2)
	r = ca.Aggregate(p7)
	assert.True(t, r.StateChange == observer.StateChange_closed)
	assert.True(t, r.AggregatedFlow.FirstFlow == p2)

	af := ca.Cache().Lookup(p1)
	assert.True(t, af.FirstFlow == p2)

	assert.True(t, af.Stats.Forward.NumFlows == 3)
	assert.True(t, af.Stats.Reply.NumFlows == 3)
	assert.True(t, af.Stats.Reply.CloseRequests == 1)
	assert.True(t, af.Stats.Forward.CloseRequests == 1)

}

func TestConnectionAggregationUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ca := NewConnectionAggregator(10*time.Second, false, true)
	go ca.Start(ctx)
	defer cancel()
	r := ca.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "UDP",
	})
	assert.True(t, r.StateChange == observer.StateChange_new|observer.StateChange_established)

	r = ca.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		ProtocolStr: "UDP",
		Reply:       true,
	})
	assert.True(t, r.StateChange == observer.StateChange_first_reply)
	assert.True(t, r.Reply)

	// Different flow
	r = ca.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("3.3.3.3"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "UDP",
	})
	assert.True(t, r.StateChange == observer.StateChange_new|observer.StateChange_established)

	// Different flow reply
	r = ca.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		Destination: testflow.Peer{IP: net.ParseIP("3.3.3.3"), Port: 1000},
		ProtocolStr: "UDP",
		Reply:       true,
	})
	assert.True(t, r.StateChange == observer.StateChange_first_reply)
	assert.True(t, r.Reply)

	af := ca.Cache().Lookup(&testflow.Flow{
		Source:      testflow.Peer{IP: net.ParseIP("1.1.1.1"), Port: 1000},
		Destination: testflow.Peer{IP: net.ParseIP("2.2.2.2"), Port: 22},
		ProtocolStr: "UDP",
	})

	assert.True(t, af.Stats.Forward.NumFlows == 1)
	assert.True(t, af.Stats.Reply.NumFlows == 1)
}

func TestCompareDNS(t *testing.T) {
	type testDef struct {
		a      *observer.DNS
		b      *observer.DNS
		result bool
	}

	matrix := []testDef{
		{a: &observer.DNS{}, b: &observer.DNS{}, result: true},
		{a: &observer.DNS{Qtypes: []string{"A"}, Query: "example.org"}, b: &observer.DNS{Qtypes: []string{"A"}, Query: "example.org"}, result: true},
		{a: &observer.DNS{Qtypes: []string{"A"}, Query: "example.org"}, b: &observer.DNS{Qtypes: []string{"A"}, Query: "isovalent.com"}, result: false},
		{a: &observer.DNS{Qtypes: []string{"AAAA", "A"}, Query: "example.org"}, b: &observer.DNS{Qtypes: []string{"A", "AAAA"}, Query: "example.org"}, result: true},
	}

	for _, test := range matrix {
		assert.EqualValues(t, looseCompareDNS(test.a, test.b), test.result)
	}
}

func TestCompareHTTP(t *testing.T) {
	type testDef struct {
		a      *observer.HTTP
		b      *observer.HTTP
		result bool
	}

	matrix := []testDef{
		{a: &observer.HTTP{}, b: &observer.HTTP{}, result: true},
		{a: &observer.HTTP{Code: 10}, b: &observer.HTTP{Code: 10}, result: true},
		{a: &observer.HTTP{Code: 10}, b: &observer.HTTP{Code: 20}, result: false},
		{a: &observer.HTTP{Method: "GET"}, b: &observer.HTTP{Method: "GET"}, result: true},
		{a: &observer.HTTP{Method: "GET"}, b: &observer.HTTP{Method: "POST"}, result: false},
		{a: &observer.HTTP{Method: "GET", Url: "/path"}, b: &observer.HTTP{Method: "GET", Url: "/path"}, result: true},
		{a: &observer.HTTP{Method: "GET", Url: "/path?id=1234"}, b: &observer.HTTP{Method: "GET", Url: "/path?id=4567"}, result: true},
		{a: &observer.HTTP{Method: "GET", Url: "/path"}, b: &observer.HTTP{Method: "GET", Url: "/other"}, result: false},
		{a: &observer.HTTP{Protocol: "HTTP"}, b: &observer.HTTP{Protocol: "HTTP"}, result: true},
		{a: &observer.HTTP{Protocol: "HTTP"}, b: &observer.HTTP{Protocol: "HTTP/2"}, result: false},
		// HTTP header must be ignored in comparison
		{
			a:      &observer.HTTP{Method: "GET", Headers: []*observer.HTTPHeader{{Key: "foo", Value: "value"}}},
			b:      &observer.HTTP{Method: "GET"},
			result: true,
		},
	}

	for _, test := range matrix {
		assert.EqualValues(t, looseCompareHTTP(test.a, test.b), test.result)
	}
}

func TestCompareKafka(t *testing.T) {
	type testDef struct {
		a      *observer.Kafka
		b      *observer.Kafka
		result bool
	}

	matrix := []testDef{
		{a: &observer.Kafka{}, b: &observer.Kafka{}, result: true},
		{a: &observer.Kafka{ErrorCode: 10}, b: &observer.Kafka{ErrorCode: 10}, result: true},
		{a: &observer.Kafka{ErrorCode: 10}, b: &observer.Kafka{ErrorCode: 20}, result: false},
		{a: &observer.Kafka{ErrorCode: 10, ApiKey: "foo"}, b: &observer.Kafka{ErrorCode: 10, ApiKey: "foo"}, result: true},
		{a: &observer.Kafka{ErrorCode: 10, ApiKey: "foo"}, b: &observer.Kafka{ErrorCode: 10, ApiKey: "bar"}, result: false},
		{a: &observer.Kafka{ApiVersion: 10}, b: &observer.Kafka{ApiVersion: 10}, result: true},
		{a: &observer.Kafka{ApiVersion: 10}, b: &observer.Kafka{ApiVersion: 20}, result: false},
		{a: &observer.Kafka{CorrelationId: 10}, b: &observer.Kafka{CorrelationId: 10}, result: true},
		{a: &observer.Kafka{CorrelationId: 10}, b: &observer.Kafka{CorrelationId: 20}, result: false},
		{a: &observer.Kafka{ErrorCode: 10, Topic: "foo"}, b: &observer.Kafka{ErrorCode: 10, Topic: "foo"}, result: true},
		{a: &observer.Kafka{ErrorCode: 10, Topic: "foo"}, b: &observer.Kafka{ErrorCode: 10, Topic: "bar"}, result: false},
	}

	for _, test := range matrix {
		assert.EqualValues(t, compareKafka(test.a, test.b), test.result)
	}
}

func TestConnectionExpiration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ca := NewConnectionAggregator(1*time.Second, false, false)
	go ca.Start(ctx)
	defer cancel()
	flow := testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		ProtocolStr: "TCP",
	}

	// The first flow shows up. The connection aggregator sets "new" state change flags. The "new"
	// flag matches the default state change filter, which causes the initial flow to be included
	// in the GetFlows() response.
	result := ca.Aggregate(&flow)
	assert.Equal(t, observer.StateChange_new, result.StateChange)

	for i := 0; i < 100; i++ {
		// Subsequent aggregations don't set any state change flag until the flow expires from
		// the aggregation cache. Flows without any state change flags don't get included in
		// the GetFlows() response.
		result = ca.Aggregate(&flow)

		// The flow expires after 1 second, and the next flow gets the "new" flags again.
		if result.StateChange == observer.StateChange_new {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	assert.Fail(t, "flow didn't expire")
}
