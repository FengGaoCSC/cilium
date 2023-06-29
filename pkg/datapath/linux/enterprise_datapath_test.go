//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package linux

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

func TestInjectCEPrefixClusterMutator(t *testing.T) {
	tests := []struct {
		name     string
		cmcfg    cecmcfg.Config
		localID  uint32
		nodeID   uint32
		expected uint32
	}{
		{
			name:     "cluster-aware addressing disabled",
			localID:  11,
			nodeID:   22,
			expected: 0,
		},
		{
			name:     "cluster-aware addressing enabled, local node",
			cmcfg:    cecmcfg.Config{EnableClusterAwareAddressing: true},
			localID:  11,
			nodeID:   11,
			expected: 0,
		},
		{
			name:     "cluster-aware addressing enabled, remote node",
			cmcfg:    cecmcfg.Config{EnableClusterAwareAddressing: true},
			localID:  11,
			nodeID:   22,
			expected: 22,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nh := linuxNodeHandler{}
			nh.SetPrefixClusterMutatorFn(func(n *types.Node) []cmtypes.PrefixClusterOpts { return nil })

			dp := linuxDatapath{node: &nh}
			InjectCEPrefixClusterMutator(&dp, tt.cmcfg, &option.DaemonConfig{ClusterID: tt.localID})

			mutators := nh.prefixClusterMutatorFn(&types.Node{ClusterID: tt.nodeID})
			pc := cmtypes.PrefixClusterFromCIDR(cidr.MustParseCIDR("1.2.3.4/32"), mutators...)
			assert.Equal(t, tt.expected, pc.ClusterID())
		})
	}
}
