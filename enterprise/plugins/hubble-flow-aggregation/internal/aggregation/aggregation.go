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
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/chain"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"

	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ConfigureAggregator configures a set of aggregators as a chain
func ConfigureAggregator(ctx context.Context, aggregators []*observer.Aggregator) (types.Aggregator, error) {
	var as []types.Aggregator
	ttl := 30 * time.Second
	renewTTL := true

	for _, requestedAggregator := range aggregators {
		var a types.Aggregator
		if requestedAggregator.Ttl != nil {
			ttl = requestedAggregator.Ttl.AsDuration()
		}
		if requestedAggregator.RenewTtl != nil {
			renewTTL = requestedAggregator.RenewTtl.Value
		}

		switch requestedAggregator.Type {
		case observer.AggregatorType_connection:
			a = NewConnectionAggregator(ctx, ttl, requestedAggregator.IgnoreSourcePort, renewTTL)
		case observer.AggregatorType_identity:
			a = NewIdentityAggregator(ctx, ttl, renewTTL)
		default:
			return nil, fmt.Errorf("unknown aggregator: %d", requestedAggregator.Type)
		}

		as = append(as, a)
	}

	switch len(as) {
	case 0:
		return nil, nil
	case 1:
		return as[0], nil
	default:
		return chain.NewAggregationChain(as), nil
	}
}

func GetAggregation(
	aggregators []string,
	filters []string,
	ignoreSourcePort bool,
	ttl time.Duration,
	renewTTL bool) (*observer.Aggregation, error) {
	agg := observer.Aggregation{}
	if len(aggregators) > 0 {
		for _, f := range filters {
			v, ok := observer.StateChange_value[f]
			if !ok {
				return nil, fmt.Errorf("unknown state change: %s", f)
			}
			agg.StateChangeFilter |= observer.StateChange(v)
		}
		for _, a := range aggregators {
			t, ok := observer.AggregatorType_value[a]
			if !ok {
				return nil, fmt.Errorf("unknown aggregator: %s", a)
			}
			agg.Aggregators = append(agg.Aggregators, &observer.Aggregator{
				Type:             observer.AggregatorType(t),
				IgnoreSourcePort: ignoreSourcePort,
				Ttl:              durationpb.New(ttl),
				RenewTtl:         &wrappers.BoolValue{Value: renewTTL},
			})
		}
	}
	return &agg, nil
}
