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
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"

	"github.com/cilium/lumberjack/v2"
)

const formatVersionV1 = "v1"

var (
	_ plugins.ServerOptions        = (*export)(nil)
	_ observeroption.OnDecodedFlow = (*export)(nil)
	_ observeroption.OnServerInit  = (*export)(nil)
)

func (e *export) OnServerInit(_ observeroption.Server) error {
	conf := getConfigFromViper()
	e.enabled = (conf.filePath != "")
	if !e.enabled {
		e.logger.Info("Disabling JSON export")
		return nil
	}
	jsonExportLog := &lumberjack.Logger{
		Filename:   conf.filePath,
		MaxSize:    conf.fileMaxSize,
		MaxBackups: conf.fileMaxBackups,
		Compress:   conf.fileCompress,
	}
	if conf.fileRotationInterval != 0 {
		e.logger.WithField("duration", conf.fileRotationInterval).Info("Periodically rotating JSON export files")
		go func() {
			ticker := time.NewTicker(conf.fileRotationInterval)
			for range ticker.C {
				if rotationErr := jsonExportLog.Rotate(); rotationErr != nil {
					e.logger.WithError(rotationErr).
						WithField("filename", conf.filePath).
						Warn("Failed to rotate JSON export file")
				}
			}
		}()
	}

	var logWriter io.Writer = jsonExportLog
	if e.metricsHandler != nil {
		logWriter = e.metricsHandler.newExportedBytesCounterWriter(logWriter)
	}
	e.encoder = json.NewEncoder(logWriter)
	e.formatVersion = conf.formatVersion
	if conf.rateLimit >= 0 {
		e.rateLimiter = newRateLimiter(1*time.Minute, conf.rateLimit, e)
	}
	var err error
	if e.allowlist, err = buildFilterFuncs(conf.flowAllowlist); err != nil {
		e.logger.WithError(err).WithField("allowlist", conf.flowAllowlist).Warn("Failed to build allowlist filter functions")
		return err
	}
	if e.denylist, err = buildFilterFuncs(conf.flowDenylist); err != nil {
		e.logger.WithError(err).WithField("denylist", conf.flowDenylist).Warn("Failed to build denylist filter functions")
		return err
	}
	// Initialize aggregation context if the aggregation plugin is enabled.
	if e.aggregationPlugin != nil {
		e.logger.Info("Enabling aggregation for json export")
		e.aggregationContext, err = e.aggregationPlugin.GetAggregationContext(
			conf.aggregation,
			conf.aggregationStateFilter,
			conf.aggregationIgnoreSourcePort,
			conf.aggregationTTL,
			conf.aggregationRenewTTL)
		if err != nil {
			return err
		}
	}

	e.nodeName = conf.nodeName
	e.logger.WithField("config", fmt.Sprintf("%+v", conf)).Info("Initialized atlantis export plugin")
	return nil
}

func (e *export) exportFlow(ctx context.Context, f *flowpb.Flow) error {
	if e.rateLimiter != nil && !e.rateLimiter.Allow() {
		atomic.AddUint64(&e.rateLimiter.dropped, 1)
		return nil
	}
	nodeName := f.NodeName
	if e.nodeName != "" {
		// Override node_name with the value specified in --export-node-name flag.
		nodeName = e.nodeName
	}

	if e.metricsHandler != nil {
		err := e.metricsHandler.updateMetrics(ctx, f)
		if err != nil {
			return err
		}
	}

	if e.formatVersion == formatVersionV1 {
		return e.encoder.Encode(&observer.GetFlowsResponse{
			ResponseTypes: &observer.GetFlowsResponse_Flow{Flow: f},
			NodeName:      nodeName,
			Time:          f.Time,
		})
	}

	return e.encoder.Encode(f)
}

func (e *export) OnDecodedFlow(ctx context.Context, f *flowpb.Flow) (bool, error) {
	if !e.enabled {
		return false, nil
	}
	if !filters.Apply(e.allowlist, e.denylist, &v1.Event{Event: f}) {
		return false, nil
	}
	if e.aggregationPlugin == nil {
		return false, e.exportFlow(ctx, f)
	}
	// The aggregation plugin is enabled. Pass the flow to the aggregation plugin
	// to determine if the flow needs to be exported.
	stop, err := e.aggregationPlugin.OnFlowDelivery(e.aggregationContext, f)
	if err != nil {
		e.logger.WithError(err).Warn("aggregation.OnFlowDelivery failed")
		return false, err
	}
	// Only call exportFlow if stop is false, meaning that the aggregation plugin detected
	// a state change. Note that this function still returns stop=false even if the aggregation
	// plugin returns stop=true. Otherwise these flows will not be put into the ring buffer,
	// and other GetFlowsRequests will never see them.
	if !stop {
		if err := e.exportFlow(ctx, f); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (e *export) ServerOptions() []observeroption.Option {
	return []observeroption.Option{
		observeroption.WithOnServerInit(e),
		observeroption.WithOnDecodedFlow(e),
	}
}
