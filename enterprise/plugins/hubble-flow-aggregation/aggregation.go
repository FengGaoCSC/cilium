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

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
)

type contextKey string

var (
	aggregatorKey = contextKey("aggregator")
	requestKey    = contextKey("request")
)

func (p *flowAggregation) OnGetFlows(ctx context.Context, req *observer.GetFlowsRequest) (context.Context, error) {
	if req.Aggregation != nil {
		aggregator, err := aggregation.ConfigureAggregator(ctx, req.Aggregation.Aggregators)
		p.logger.Debugf("Configured flow aggregator %#v", aggregator)
		if err != nil {
			return ctx, err
		}

		ctx = context.WithValue(ctx, aggregatorKey, aggregator)
		return context.WithValue(ctx, requestKey, req), nil
	}

	return ctx, nil
}

func (p *flowAggregation) OnFlowDelivery(ctx context.Context, f *flow.Flow) (bool, error) {
	// Ideally Cilium shouldn't call OnFlowDelivery if the event is LostEvent, but it's better
	// to check if f is nil here to be safe anyways.
	//
	// https://github.com/cilium/cilium/blob/1.10.4/pkg/hubble/observer/local_observer.go#L319
	if f == nil {
		return false, nil
	}

	aggregator, ok := ctx.Value(aggregatorKey).(types.Aggregator)
	if !ok {
		return false, nil
	}

	req, ok := ctx.Value(requestKey).(*observer.GetFlowsRequest)
	if !ok {
		return false, nil
	}

	result := aggregator.Aggregate(&aggregation.AggregatableFlow{Flow: f})
	if result != nil && (result.StateChange&req.Aggregation.StateChangeFilter) == 0 {
		return true, nil
	}

	return false, nil
}

// GetAggregationContext returns a context that can be used with OnFlowDelivery() to perform
// aggregation with the given configuration parameters.
func (p *flowAggregationPlugin) GetAggregationContext(
	aggregators []string,
	filters []string,
	ignoreSourcePort bool,
	ttl time.Duration,
	renewTTL bool) (context.Context, error) {
	agg, err := aggregation.GetAggregation(aggregators, filters, ignoreSourcePort, ttl, renewTTL)
	if err != nil {
		return nil, err
	}
	return p.OnGetFlows(context.Background(), &observer.GetFlowsRequest{Aggregation: agg})
}
