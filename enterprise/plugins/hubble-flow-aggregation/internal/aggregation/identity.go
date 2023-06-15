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
	"time"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/cache"

	"github.com/cilium/cilium/api/v1/observer"
)

func newIdentityAggregation(f types.AggregatableFlow) *connectionAggregation {
	return &connectionAggregation{
		AggregatableFlow: f,
		addrType:         types.AddrTypeIdentity,
		ignoreSourcePort: true,
	}
}

func aggregateIdentity(a *types.AggregatedFlow, _ *observer.DirectionStatistics, _ types.AggregatableFlow, r *types.Result) {
	if !a.Stats.Established {
		r.StateChange |= observer.StateChange_established
		a.Stats.Established = true
	}
}

func identityCompareFunc(a, b types.AggregatableFlow) bool {
	ca1, ca2 := newIdentityAggregation(a), newIdentityAggregation(b)
	return ca1.Compare(ca2)
}

func identityHashFunc(f types.AggregatableFlow) types.Hash {
	return newIdentityAggregation(f).Hash()
}

// NewIdentityAggregator returns a new aggregator which aggregates based on:
//   - Source and destination identity (as high level as possible)
//   - Destination port
//   - Verdict & drop reason
//   - Direction
func NewIdentityAggregator(ctx context.Context, expiration time.Duration, renewTTL bool) *Aggregator {
	return NewAggregator(ctx, cache.Configuration{
		CompareFunc:   identityCompareFunc,
		HashFunc:      identityHashFunc,
		AggregateFunc: aggregateIdentity,
		Expiration:    expiration,
		RenewTTL:      renewTTL,
	})
}
