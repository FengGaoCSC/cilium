//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ctnat

import (
	"strconv"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")

	// Override the map names to avoid clashing with the real ones.
	ctmap.ClusterOuterMapNameTestOverride("test_ce")
	nat.ClusterOuterMapNameTestOverride("test_ce")
	option.Config.NATMapEntriesGlobal = option.NATMapEntriesGlobalDefault

	tb.Cleanup(func() {
		ctmap.CleanupPerClusterCTMaps(true, true)
		nat.CleanupPerClusterNATMaps(true, true)
	})
}

// The mapType type is private, so we cannot directly use ClusterOuterMapName
// and ClusterInnerMapName. Additionally, we only check TCP maps for brevity
// (the full checks are performed by the relevant ctmap tests).
func ctname(family nat.IPFamily, clusterID ...uint32) string {
	name := "test_ce_cilium_per_cluster_ct_tcp4"
	if family == nat.IPv6 {
		name = "test_ce_cilium_per_cluster_ct_tcp6"
	}

	if len(clusterID) == 1 {
		name = name + "_" + strconv.FormatUint(uint64(clusterID[0]), 10)
	}

	return name
}

func TestPerClusterMapsLifecycle(t *testing.T) {
	setup(t)

	tests := []struct {
		name string
		cfg  cecmcfg.Config
		dcfg *option.DaemonConfig
		init func(t *testing.T)

		assertV4 func(require.TestingT, string, ...interface{})
		assertV6 func(require.TestingT, string, ...interface{})
	}{
		{
			name: "cluster-aware addressing disabled",
			cfg:  cecmcfg.Config{EnableClusterAwareAddressing: false},
			dcfg: &option.DaemonConfig{EnableIPv4: true, EnableIPv6: false},
			init: func(t *testing.T) {
				// Create the maps to ensure that they get effectively cleaned up
				require.NoError(t, ctmap.NewPerClusterCTMaps(true, true).OpenOrCreate())
				require.NoError(t, nat.NewPerClusterNATMaps(true, true).OpenOrCreate())
			},
			assertV4: require.NoFileExists,
			assertV6: require.NoFileExists,
		},
		{
			name:     "cluster-aware addressing enabled, ipv4, ipv6",
			cfg:      cecmcfg.Config{EnableClusterAwareAddressing: true},
			dcfg:     &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true},
			init:     func(t *testing.T) {},
			assertV4: require.FileExists,
			assertV6: require.FileExists,
		},
		{
			name: "cluster-aware addressing enabled, ipv6 only",
			cfg:  cecmcfg.Config{EnableClusterAwareAddressing: true},
			dcfg: &option.DaemonConfig{EnableIPv4: false, EnableIPv6: true},
			init: func(t *testing.T) {
				// Create the IPv4 maps to ensure that they get effectively cleaned up
				require.NoError(t, ctmap.NewPerClusterCTMaps(true, false).OpenOrCreate())
				require.NoError(t, nat.NewPerClusterNATMaps(true, false).OpenOrCreate())
			},
			assertV4: require.NoFileExists,
			assertV6: require.FileExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init(t)

			maps, _ := newPerCluster(perClusterParams{
				Lifecycle:    hivetest.Lifecycle(t),
				Logger:       logging.DefaultLogger,
				Config:       tt.cfg,
				DaemonConfig: tt.dcfg,
			})

			tt.assertV4(t, bpf.MapPath(ctname(nat.IPv4)), "IPv4 CT map not correct")
			tt.assertV6(t, bpf.MapPath(ctname(nat.IPv6)), "IPv6 CT map not correct")
			tt.assertV4(t, bpf.MapPath(nat.ClusterOuterMapName(nat.IPv4)), "IPv4 NAT map not correct")
			tt.assertV6(t, bpf.MapPath(nat.ClusterOuterMapName(nat.IPv6)), "IPv6 NAT map not correct")

			require.NoError(t, maps.Update(11))
			tt.assertV4(t, bpf.MapPath(ctname(nat.IPv4, 11)), "IPv4 inner CT map not correct")
			tt.assertV6(t, bpf.MapPath(ctname(nat.IPv6, 11)), "IPv6 inner CT map  not correct")
			tt.assertV4(t, bpf.MapPath(nat.ClusterInnerMapName(nat.IPv4, 11)), "IPv4 inner NAT map not correct")
			tt.assertV6(t, bpf.MapPath(nat.ClusterInnerMapName(nat.IPv6, 11)), "IPv6 inner NAT map not correct")

			require.NoError(t, maps.Delete(11))
			require.NoFileExists(t, bpf.MapPath(ctname(nat.IPv4, 11)), "IPv4 inner CT map incorrectly present")
			require.NoFileExists(t, bpf.MapPath(ctname(nat.IPv6, 11)), "IPv6 inner CT map incorrectly present")
			require.NoFileExists(t, bpf.MapPath(nat.ClusterInnerMapName(nat.IPv4, 11)), "IPv4 inner NAT map incorrectly present")
			require.NoFileExists(t, bpf.MapPath(nat.ClusterInnerMapName(nat.IPv6, 11)), "IPv6 inner NAT map incorrectly present")
		})
	}
}
