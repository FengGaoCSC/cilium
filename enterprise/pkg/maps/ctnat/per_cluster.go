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
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	fakect "github.com/cilium/cilium/pkg/maps/ctmap/fake"
	ctmapgc "github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/nat"
	fakenat "github.com/cilium/cilium/pkg/maps/nat/fake"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

// PerCluster allows to manage per-cluster maps.
type PerCluster interface {
	// Update ensures that the per-cluster maps associated with the given ID
	// are present. It is a no-op in case cluster-aware addressing is disabled.
	Update(clusterID uint32) error
	// Delete deletes the per-cluster maps associated with the given ID.
	// It is a no-op in case cluster-aware addressing is disabled.
	Delete(clusterID uint32) error
}

type perClusterParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Logger    logrus.FieldLogger

	Config       cecmcfg.Config
	DaemonConfig *option.DaemonConfig
}

func newPerCluster(p perClusterParams) (PerCluster, ctmapgc.PerClusterCTMapsRetriever) {
	maps := perCluster{
		ct: ctmap.NewPerClusterCTMaps(
			p.DaemonConfig.IPv4Enabled(),
			p.DaemonConfig.IPv6Enabled(),
		),
		nat: nat.NewPerClusterNATMaps(
			p.DaemonConfig.IPv4Enabled(),
			p.DaemonConfig.IPv6Enabled(),
		),
	}

	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			if p.Config.EnableClusterAwareAddressing {
				p.Logger.WithFields(logrus.Fields{
					logfields.IPv4: p.DaemonConfig.IPv4Enabled(),
					logfields.IPv6: p.DaemonConfig.IPv6Enabled(),
				}).Info("Initializing per-cluster CT/NAT maps")

				if err := maps.openOrCreate(); err != nil {
					return fmt.Errorf("failed to initialize per-cluster CT/NAT maps: %w", err)
				}

				// Since it is theoretically possible that users first enable IPv4/IPv6 and disable
				// one of them afterwards, we still need to cleanup. Reverse the enabled flags
				// since we want to delete the maps for disabled address family.
				cleanupPerCluster(p.Logger, !p.DaemonConfig.IPv4Enabled(), !p.DaemonConfig.IPv6Enabled())
			} else {
				// When users enable cluster-aware addressing at some point and disable it later,
				// we should have per-cluster maps left on the bpffs. We need to delete them when
				// users no longer need it.
				cleanupPerCluster(p.Logger, true, true)
			}

			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			if p.Config.EnableClusterAwareAddressing {
				maps.close()
			}
			return nil
		},
	})

	if !p.Config.EnableClusterAwareAddressing {
		return perClusterDisabled{}, nil
	}

	return &maps, maps.ct.GetAllClusterCTMaps
}

func cleanupPerCluster(log logrus.FieldLogger, ipv4, ipv6 bool) {
	if err := ctmap.CleanupPerClusterCTMaps(ipv4, ipv6); err != nil {
		log.WithError(err).Warning("Failed to cleanup per-cluster CT maps")
	}

	if err := nat.CleanupPerClusterNATMaps(ipv4, ipv6); err != nil {
		log.WithError(err).Warning("Failed to cleanup per-cluster NAT maps")
	}
}

type perCluster struct {
	ct  ctmap.PerClusterCTMapper
	nat nat.PerClusterNATMapper
}

func (maps *perCluster) openOrCreate() error {
	if err := maps.ct.OpenOrCreate(); err != nil {
		return fmt.Errorf("CT maps: %w", err)
	}

	if err := maps.nat.OpenOrCreate(); err != nil {
		return fmt.Errorf("NAT maps: %w", err)
	}

	return nil
}

func (maps *perCluster) close() {
	maps.ct.Close()
	maps.nat.Close()
}

func (maps *perCluster) Update(clusterID uint32) error {
	if err := maps.ct.CreateClusterCTMaps(clusterID); err != nil {
		return fmt.Errorf("CT maps: %w", err)
	}

	if err := maps.nat.CreateClusterNATMaps(clusterID); err != nil {
		return fmt.Errorf("NAT maps: %w", err)
	}

	return nil
}

func (maps *perCluster) Delete(clusterID uint32) error {
	var errs error

	if err := maps.ct.DeleteClusterCTMaps(clusterID); err != nil {
		errs = fmt.Errorf("CT maps: %w", err)
	}

	if err := maps.nat.DeleteClusterNATMaps(clusterID); err != nil {
		errs = errors.Join(errs, fmt.Errorf("NAT maps: %w", err))
	}

	return errs
}

type perClusterDisabled struct{}

func (perClusterDisabled) Update(clusterID uint32) error { return nil }
func (perClusterDisabled) Delete(clusterID uint32) error { return nil }

// FakePerCluster implements the PerCluster interface for testing purposes.
type FakePerCluster struct{ *perCluster }

// NewFakePerCluster returns a PerCluster implementation that can be used
// for testing purposes.
func NewFakePerCluster(ipv4, ipv6 bool) FakePerCluster {
	return FakePerCluster{
		perCluster: &perCluster{
			ct:  fakect.NewPerClusterMaps(),
			nat: fakenat.NewPerClusterMaps(),
		},
	}
}

func (maps FakePerCluster) CT() *fakect.PerClusterMaps {
	return maps.ct.(*fakect.PerClusterMaps)
}
func (maps FakePerCluster) NAT() *fakenat.PerClusterMaps {
	return maps.nat.(*fakenat.PerClusterMaps)
}
