// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package chain

import (
	"context"
	"strings"
	"sync"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
)

// AggregationChain is a chain of aggregators. The result of the last
// aggregator is returned.
type AggregationChain struct {
	filters []types.Aggregator
}

// NewAggregationChain returns a new chained aggregator
func NewAggregationChain(f []types.Aggregator) *AggregationChain {
	return &AggregationChain{
		filters: f,
	}
}

// Add adds an additional aggregator to the chain
func (ac *AggregationChain) Add(a types.Aggregator) {
	ac.filters = append(ac.filters, a)
}

// Aggregate applies the aggregation logic of an aggregation chain
func (ac *AggregationChain) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, af := range ac.filters {
		af := af
		wg.Add(1)
		go func() {
			af.Start(ctx)
			wg.Done()
		}()
	}
	wg.Wait()
}

// Aggregate applies the aggregation logic of an aggregation chain
func (ac *AggregationChain) Aggregate(f types.AggregatableFlow) (result *types.Result) {
	for _, af := range ac.filters {
		result = af.Aggregate(f)
	}

	return
}

// String returns the AggregationChain configuration as string
func (ac *AggregationChain) String() string {
	var s []string
	for _, af := range ac.filters {
		s = append(s, af.String())
	}
	return "[" + strings.Join(s, ",") + "]"
}
