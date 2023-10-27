// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"

	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// ServerWithConfig is a container for providing interface with underlying router implementation
// and Cilium's BGP control plane related configuration.
//
// It exports a method set for manipulating the BgpServer. However, this
// struct is a dumb object. The calling code is required to keep the BgpServer's
// configuration and associated configuration fields in sync.
type ServerWithConfig struct {
	// backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	Server types.Router

	// The CiliumBGPVirtualRouter configuration which drives the configuration
	// of the above BgpServer.
	//
	// If this field is nil it means the above BgpServer has had no
	// configuration applied to it.
	Config *v2alpha1api.CiliumBGPVirtualRouter

	// Holds any announced PodCIDR routes.
	PodCIDRAnnouncements []*types.Path

	// Holds any announced Service routes.
	ServiceAnnouncements map[resource.Key][]*types.Path

	// Holds any announced VPNv4 Announcements for SRv6 L3VPN.
	SRv6L3VPNAnnouncements map[uint32]entTypes.VPNv4Advertisement

	// Holds any announced SRv6 locators
	SRv6LocatorAnnouncements []*types.Path

	// Holds peer => password mappings
	NeighborReconcilerMetadata NeighborReconcilerMetadata
}

// NewServerWithConfig will start an underlying BgpServer utilizing types.ServerParameters
// for its initial configuration.
//
// The returned ServerWithConfig has a nil CiliumBGPVirtualRouter config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BgpServer along with calling the
// underlying BgpServer's Stop() method.
func NewServerWithConfig(ctx context.Context, params types.ServerParameters) (*ServerWithConfig, error) {
	s, err := gobgp.NewGoBGPServerWithConfig(ctx, log, params)
	if err != nil {
		return nil, err
	}

	return &ServerWithConfig{
		Server:                     s,
		Config:                     nil,
		PodCIDRAnnouncements:       []*types.Path{},
		ServiceAnnouncements:       make(map[resource.Key][]*types.Path),
		SRv6L3VPNAnnouncements:     make(map[uint32]entTypes.VPNv4Advertisement),
		SRv6LocatorAnnouncements:   []*types.Path{},
		NeighborReconcilerMetadata: make(NeighborReconcilerMetadata),
	}, nil
}
