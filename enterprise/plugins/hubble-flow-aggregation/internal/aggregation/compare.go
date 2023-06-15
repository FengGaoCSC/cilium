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

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/cache"
)

// Name is the name of the compare aggregator
const Name = "compare"

// Aggregator is a basic aggregator performing aggregation based on comparison
// with existing flows in a cache
type Aggregator struct {
	cache *cache.Cache
}

// NewAggregator returns a new compare aggregator
func NewAggregator(ctx context.Context, conf cache.Configuration) *Aggregator {
	return &Aggregator{cache: cache.NewCache(ctx, conf)}
}

// Aggregate applies the aggregation logic of a compare aggregator
func (a *Aggregator) Aggregate(f types.AggregatableFlow) *types.Result {
	return a.cache.Aggregate(f)
}

// String returns the RandomAggregator configuration as string
func (a *Aggregator) String() string {
	return Name
}

// Cache returns the cache being used for comparison
func (a *Aggregator) Cache() *cache.Cache {
	return a.cache
}
