// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"fmt"
	"io"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	metricsAPI "github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/prometheus/client_golang/prometheus"
)

func (e *export) NewHandler() metricsAPI.Handler {
	if e.metricsHandler == nil {
		e.metricsHandler = &metricsHandler{}
	}
	return e.metricsHandler
}

func (e *export) HelpText() string {
	return `export - Generic flow export metrics
Reports metrics related to exporting flows

Metrics:
  hubble_flows_exported_total                Number of flows exported
  hubble_flows_exported_bytes_total          Number of bytes exported for flows
  hubble_flows_last_exported_timestamp       Timestamp of the most recent flow to be exported

Options:` +
		metricsAPI.ContextOptionsHelp
}

type metricsHandler struct {
	flowsExportedTotal      *prometheus.CounterVec
	flowsExportedBytesTotal prometheus.Counter
	flowsExportTimestamp    prometheus.Gauge
	context                 *metricsAPI.ContextOptions
}

func (h *metricsHandler) Init(registry *prometheus.Registry, options metricsAPI.Options) error {
	c, err := metricsAPI.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"protocol", "type", "subtype", "verdict"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.flowsExportedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_exported_total",
		Help:      "Total number of flows exported",
	}, labels)

	h.flowsExportedBytesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_exported_bytes_total",
		Help:      "Number of bytes exported for flows",
	})

	h.flowsExportTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_last_exported_timestamp",
		Help:      "Timestamp of the most recent flow to be exported",
	})

	registry.MustRegister(h.flowsExportedTotal)
	registry.MustRegister(h.flowsExportedBytesTotal)
	registry.MustRegister(h.flowsExportTimestamp)
	return nil
}

func (h *metricsHandler) Status() string {
	return h.context.Status()
}

func (h *metricsHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{
		h.flowsExportedTotal.MetricVec,
	}
}

func (h *metricsHandler) Context() *metricsAPI.ContextOptions {
	return h.context
}

// ProcessFlow is intentioanlly a no-op, as we handle the metric in the
// (*export).exportFlow method
func (h *metricsHandler) ProcessFlow(_ context.Context, _ *flowpb.Flow) error { return nil }

// processFlow is a helper method that is used by (*export).exportFlow to
// update the metric.
// It was copied from https://github.com/cilium/cilium/blob/08d571a97ff6402c8654f99c4af42afbd25848a6/pkg/hubble/metrics/flow/handler.go#L47-L81
func (h *metricsHandler) updateMetrics(_ context.Context, flow *flowpb.Flow) error {
	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	var typeName, subType string
	eventType := flow.GetEventType().GetType()
	switch eventType {
	case monitorAPI.MessageTypeAccessLog:
		typeName = "L7"
		if l7 := flow.GetL7(); l7 != nil {
			switch {
			case l7.GetDns() != nil:
				subType = "DNS"
			case l7.GetHttp() != nil:
				subType = "HTTP"
			case l7.GetKafka() != nil:
				subType = "Kafka"
			}
		}
	case monitorAPI.MessageTypeDrop:
		typeName = "Drop"
	case monitorAPI.MessageTypeCapture:
		typeName = "Capture"
	case monitorAPI.MessageTypeTrace:
		typeName = "Trace"
		subType = monitorAPI.TraceObservationPoints[uint8(flow.GetEventType().SubType)]
	case monitorAPI.MessageTypePolicyVerdict:
		typeName = "PolicyVerdict"
	default:
		typeName = "Unknown"
		subType = fmt.Sprintf("%d", eventType)
	}

	labels := []string{v1.FlowProtocol(flow), typeName, subType, flow.GetVerdict().String()}
	labels = append(labels, labelValues...)
	h.flowsExportedTotal.WithLabelValues(labels...).Inc()
	h.flowsExportTimestamp.Set(float64(flow.GetTime().Seconds))
	return nil
}

func (h *metricsHandler) newExportedBytesCounterWriter(w io.Writer) io.Writer {
	return byteCounterWriter{w, h.flowsExportedBytesTotal}
}

type byteCounterWriter struct {
	writer       io.Writer
	bytesWritten prometheus.Counter
}

func (w byteCounterWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.bytesWritten.Add(float64(n))
	return n, err
}
