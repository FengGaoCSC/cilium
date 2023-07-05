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

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"

	"github.com/sirupsen/logrus"
)

var (
	// validate interface conformity
	_ plugins.Init          = New
	_ plugins.ServerOptions = (*flowAggregationPlugin)(nil)
	_ Plugin                = (*flowAggregationPlugin)(nil)
)

type Plugin interface {
	GetAggregationContext(
		aggregators []string,
		filters []string,
		ignoreSourcePort bool,
		ttl time.Duration,
		renewTTL bool) (context.Context, error)
	OnFlowDelivery(ctx context.Context, f *flow.Flow) (bool, error)
}

type flowAggregation struct {
	logger logrus.FieldLogger
}

type flowAggregationPlugin struct {
	flowAggregation *flowAggregation
}

// New returns a new flow aggregation plugin
func New() (plugins.Instance, error) {
	return &flowAggregationPlugin{
		flowAggregation: &flowAggregation{},
	}, nil
}

func (p *flowAggregationPlugin) OnServerInit(srv observeroption.Server) error {
	p.flowAggregation.logger = srv.GetLogger()
	return nil
}

func (p *flowAggregationPlugin) ServerOptions() []observeroption.Option {
	return []observeroption.Option{
		observeroption.WithOnServerInit(p),
		observeroption.WithOnFlowDelivery(p),
		observeroption.WithOnGetFlows(p),
	}
}

func (p *flowAggregationPlugin) OnGetFlows(ctx context.Context, req *observer.GetFlowsRequest) (context.Context, error) {
	return p.flowAggregation.OnGetFlows(ctx, req)
}

func (p *flowAggregationPlugin) OnFlowDelivery(ctx context.Context, f *flow.Flow) (bool, error) {
	return p.flowAggregation.OnFlowDelivery(ctx, f)
}
