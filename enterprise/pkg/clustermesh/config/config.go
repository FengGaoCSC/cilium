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
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

const (
	// enableClusterAwareAddressing enables cluster-aware addressing
	enableClusterAwareAddressing = "enable-cluster-aware-addressing"

	// enableInterClusterSNAT enables inter-cluster SNAT
	enableInterClusterSNAT = "enable-inter-cluster-snat"
)

type Config struct {
	// EnableClusterAwareAddressing enables cluster-aware addressing
	EnableClusterAwareAddressing bool

	// EnableInterClusterSNAT enables inter-cluster SNAT
	EnableInterClusterSNAT bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(enableClusterAwareAddressing, def.EnableClusterAwareAddressing, "Enable cluster-aware addressing, to support overlapping PodCIDRs")
	flags.Bool(enableInterClusterSNAT, def.EnableInterClusterSNAT, "Enable inter-cluster SNAT, to support overlapping PodCIDRs")
}

func (cfg Config) Validate(dcfg *option.DaemonConfig) error {
	if !cfg.EnableClusterAwareAddressing {
		if cfg.EnableInterClusterSNAT {
			return fmt.Errorf("%s depends on %s", enableInterClusterSNAT, enableClusterAwareAddressing)
		}

		return nil
	}

	if !dcfg.TunnelingEnabled() {
		return fmt.Errorf("--%s depends on tunnel=%s|%s", enableClusterAwareAddressing, option.TunnelVXLAN, option.TunnelGeneve)
	}

	// We cannot rely on the EnableNodePort value only because it may be
	// mutated depending on the KPR settings. Hence, check them both.
	if dcfg.KubeProxyReplacement == option.KubeProxyReplacementDisabled ||
		(dcfg.KubeProxyReplacement == option.KubeProxyReplacementPartial && !dcfg.EnableNodePort) ||
		(dcfg.KubeProxyReplacement == option.KubeProxyReplacementFalse && !dcfg.EnableNodePort) {
		return fmt.Errorf("--%s depends on BPF NodePort", enableClusterAwareAddressing)
	}

	incompatibilities := map[string]bool{
		option.EnableEndpointRoutes:         dcfg.EnableEndpointRoutes,
		option.EnableEndpointHealthChecking: dcfg.EnableEndpointHealthChecking,
		option.EnableIPSecName:              dcfg.EnableIPSec,
		option.EnableWireguard:              dcfg.EnableWireguard,
	}

	for cfgname, enabled := range incompatibilities {
		if enabled {
			return fmt.Errorf("Currently, --%s can't be used with --%s", enableClusterAwareAddressing, cfgname)
		}
	}

	return nil
}
