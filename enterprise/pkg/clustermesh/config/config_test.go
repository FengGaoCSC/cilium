//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		dcfg      *option.DaemonConfig
		assertion func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			name: "ClusterAwareAddressing disabled",
			cfg:  Config{},
			dcfg: &option.DaemonConfig{
				RoutingMode:          option.RoutingModeNative,
				KubeProxyReplacement: option.KubeProxyReplacementDisabled,
			},
			assertion: assert.NoError,
		},
		{
			name:      "ClusterAwareAddressing disabled but InterClusterSNAT enabled",
			cfg:       Config{EnableInterClusterSNAT: true},
			dcfg:      &option.DaemonConfig{},
			assertion: assert.Error,
		},
		{
			name:      "ClusterAwareAddressing enabled and native routing mode",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{RoutingMode: option.RoutingModeNative},
			assertion: assert.Error,
		},
		{
			name:      "ClusterAwareAddressing enabled and KPR disabled",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{KubeProxyReplacement: option.KubeProxyReplacementDisabled},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR partial (NodePort disabled)",
			cfg:  Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{
				KubeProxyReplacement: option.KubeProxyReplacementPartial,
				EnableNodePort:       false,
			},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR partial (NodePort enabled)",
			cfg:  Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{
				KubeProxyReplacement: option.KubeProxyReplacementPartial,
				EnableNodePort:       true,
			},
			assertion: assert.NoError,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR false (NodePort disabled)",
			cfg:  Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{
				KubeProxyReplacement: option.KubeProxyReplacementFalse,
				EnableNodePort:       false,
			},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR false (NodePort enabled)",
			cfg:  Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{
				KubeProxyReplacement: option.KubeProxyReplacementFalse,
				EnableNodePort:       true,
			},
			assertion: assert.NoError,
		},
		{
			name:      "ClusterAwareAddressing enabled and KPR strict",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{KubeProxyReplacement: option.KubeProxyReplacementStrict},
			assertion: assert.NoError,
		},
		{
			name:      "ClusterAwareAddressing enabled and KPR true",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{KubeProxyReplacement: option.KubeProxyReplacementTrue},
			assertion: assert.NoError,
		},
		{
			name:      "ClusterAwareAddressing enabled and EndpointRoutes enabled",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{EnableEndpointRoutes: true},
			assertion: assert.Error,
		},
		{
			name:      "ClusterAwareAddressing enabled and EndpointHealthChecking enabled",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{EnableEndpointHealthChecking: true},
			assertion: assert.Error,
		},
		{
			name:      "ClusterAwareAddressing enabled and IPSec encryption enabled",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{EnableIPSec: true},
			assertion: assert.Error,
		},
		{
			name:      "ClusterAwareAddressing enabled and Wireguard encryption enabled",
			cfg:       Config{EnableClusterAwareAddressing: true},
			dcfg:      &option.DaemonConfig{EnableWireguard: true},
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.cfg.Validate(tt.dcfg))
		})
	}
}
