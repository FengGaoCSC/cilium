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
	"time"

	"github.com/cilium/cilium/daemon/cmd"
)

const (
	exportFilePath                    = "export-file-path"
	exportFileMaxSize                 = "export-file-max-size"
	exportFileRotationInterval        = "export-file-rotation-interval"
	exportFileMaxBackups              = "export-file-max-backups"
	exportFileCompress                = "export-file-compress"
	exportFlowWhitelist               = "export-flow-whitelist"
	exportFlowBlacklist               = "export-flow-blacklist"
	exportFlowAllowlist               = "export-flow-allowlist"
	exportFlowDenylist                = "export-flow-denylist"
	exportAggregation                 = "export-aggregation"
	exportAggregationIgnoreSourcePort = "export-aggregation-ignore-source-port"
	exportAggregationRenewTTL         = "export-aggregation-renew-ttl"
	exportAggregationStateFilter      = "export-aggregation-state-filter"
	exportAggregationTTL              = "export-aggregation-ttl"
	exportFormatVersion               = "export-format-version"
	exportRateLimit                   = "export-rate-limit"
	exportNodeName                    = "export-node-name"
)

type config struct {
	filePath                    string
	fileMaxSize                 int
	fileRotationInterval        time.Duration
	fileMaxBackups              int
	fileCompress                bool
	flowAllowlist               string
	flowDenylist                string
	aggregation                 []string
	aggregationIgnoreSourcePort bool
	aggregationRenewTTL         bool
	aggregationStateFilter      []string
	aggregationTTL              time.Duration
	formatVersion               string
	rateLimit                   int
	nodeName                    string
}

func getConfigFromViper() *config {
	// instead of using the global viper, use the agent local instance
	vp := cmd.Vp

	// --export-flow-{allow,deny}list take precedence over deprecated --export-flow-{white,black}list.
	allowlist := vp.GetString(exportFlowAllowlist)
	if allowlist == "" {
		allowlist = vp.GetString(exportFlowWhitelist)
	}
	denylist := vp.GetString(exportFlowDenylist)
	if denylist == "" {
		denylist = vp.GetString(exportFlowBlacklist)
	}
	return &config{
		filePath:                    vp.GetString(exportFilePath),
		fileMaxSize:                 vp.GetInt(exportFileMaxSize),
		fileRotationInterval:        vp.GetDuration(exportFileRotationInterval),
		fileMaxBackups:              vp.GetInt(exportFileMaxBackups),
		fileCompress:                vp.GetBool(exportFileCompress),
		flowAllowlist:               allowlist,
		flowDenylist:                denylist,
		aggregation:                 vp.GetStringSlice(exportAggregation),
		aggregationIgnoreSourcePort: vp.GetBool(exportAggregationIgnoreSourcePort),
		aggregationRenewTTL:         vp.GetBool(exportAggregationRenewTTL),
		aggregationStateFilter:      vp.GetStringSlice(exportAggregationStateFilter),
		aggregationTTL:              vp.GetDuration(exportAggregationTTL),
		formatVersion:               vp.GetString(exportFormatVersion),
		rateLimit:                   vp.GetInt(exportRateLimit),
		nodeName:                    vp.GetString(exportNodeName),
	}
}
