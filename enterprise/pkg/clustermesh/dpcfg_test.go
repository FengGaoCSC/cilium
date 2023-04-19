//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

func TestDatapathNodeHeaderConfigProvider(t *testing.T) {
	localNode, err := node.NewLocalNodeStore(
		node.LocalNodeStoreParams{Lifecycle: hivetest.Lifecycle(t)})
	assert.NoError(t, err)
	localNode.Update(func(ln *node.LocalNode) { ln.SetNodeInternalIP(net.ParseIP("1.2.3.4")) })

	tests := []struct {
		name     string
		cfg      cecmcfg.Config
		dcfg     *option.DaemonConfig
		expected dpcfgdef.Map
	}{
		{
			name:     "ClusterAwareAddressing disabled",
			cfg:      cecmcfg.Config{},
			dcfg:     &option.DaemonConfig{ClusterID: 10},
			expected: dpcfgdef.Map{},
		},
		{
			name: "ClusterAwareAddressing enabled",
			cfg:  cecmcfg.Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{ClusterID: 10},
			expected: dpcfgdef.Map{
				"CLUSTER_ID":                      "10",
				"ENABLE_CLUSTER_AWARE_ADDRESSING": "1",
			},
		},
		{
			name: "ClusterAwareAddressing and EnableInterClusterSNAT enabled, ipv4 disabled",
			cfg:  cecmcfg.Config{EnableClusterAwareAddressing: true, EnableInterClusterSNAT: true},
			dcfg: &option.DaemonConfig{ClusterID: 10},
			expected: dpcfgdef.Map{
				"CLUSTER_ID":                      "10",
				"ENABLE_CLUSTER_AWARE_ADDRESSING": "1",
				"ENABLE_INTER_CLUSTER_SNAT":       "1",
			},
		},
		{
			name: "ClusterAwareAddressing and EnableInterClusterSNAT enabled, ipv4 enabled",
			cfg:  cecmcfg.Config{EnableClusterAwareAddressing: true, EnableInterClusterSNAT: true},
			dcfg: &option.DaemonConfig{ClusterID: 10, EnableIPv4: true},
			expected: dpcfgdef.Map{
				"CLUSTER_ID":                      "10",
				"ENABLE_CLUSTER_AWARE_ADDRESSING": "1",
				"ENABLE_INTER_CLUSTER_SNAT":       "1",
				"IPV4_INTER_CLUSTER_SNAT":         "0x04030201",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := datapathNodeHeaderConfigProvider(tt.cfg, tt.dcfg, localNode).Fn()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
