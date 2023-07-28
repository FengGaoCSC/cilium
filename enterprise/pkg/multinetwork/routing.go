// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/maps"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeUpdater interface {
	UpdateLocalNode()
}

type nodeIPPair struct {
	ipv4 net.IP
	ipv6 net.IP
}

func (n nodeIPPair) Equal(o nodeIPPair) bool {
	return n.ipv4.Equal(o.ipv4) && n.ipv6.Equal(o.ipv6)
}

const (
	localNodeSyncController = "multi-network-sync-local-node-ip"
	isovalentNetworkIP      = "isovalent.com/v1alpha1/NetworkIP"
)

func newNetworkAddressingType(networkName string) addressing.AddressType {
	return addressing.AddressType(isovalentNetworkIP + ":" + networkName)
}

func extractNetwork(addressType addressing.AddressType) (networkName string, ok bool) {
	ipType, network, ok := strings.Cut(string(addressType), ":")
	if !ok || ipType != isovalentNetworkIP {
		return "", false
	}

	return network, true
}

type localNetworkIPCollector struct {
	daemonConfig daemonConfig

	networkStore resource.Store[*iso_v1alpha1.IsovalentPodNetwork]

	mutex               lock.Mutex // protects nodeIPByNetworkName
	nodeIPByNetworkName map[string]nodeIPPair
}

func (m *localNetworkIPCollector) GetNodeAddresses() []nodeTypes.Address {
	if m.networkStore == nil {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	nodeAddresses := make([]nodeTypes.Address, 0, len(m.nodeIPByNetworkName))
	for network, nodeIP := range m.nodeIPByNetworkName {
		if nodeIP.ipv4 != nil {
			nodeAddresses = append(nodeAddresses, nodeTypes.Address{
				Type: newNetworkAddressingType(network),
				IP:   nodeIP.ipv4,
			})
		}
		if nodeIP.ipv6 != nil {
			nodeAddresses = append(nodeAddresses, nodeTypes.Address{
				Type: newNetworkAddressingType(network),
				IP:   nodeIP.ipv6,
			})
		}
	}

	return nodeAddresses
}

func collectLocalNodeIPs(ifaces []netlink.Link, family int) []net.IP {
	nodeIPs := make([]net.IP, 0, len(ifaces))
	for _, iface := range ifaces {
		scopedLog := log.WithField(logfields.Interface, iface.Attrs().Name)

		addrs, err := netlink.AddrList(iface, family)
		if err != nil {
			scopedLog.
				WithError(err).
				Warn("Failed to list addresses on interface. Local node IPs on this interface will be ignored.")
			continue
		}

		for _, addr := range addrs {
			nodeIPs = append(nodeIPs, addr.IP)
		}
	}

	return nodeIPs
}

func (m *localNetworkIPCollector) updateNodeIPAddresses(nodeUpdater nodeUpdater) error {
	ifaces, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list node interfaces: %w", err)
	}

	var nodeIPv4, nodeIPv6 []net.IP
	if m.daemonConfig.IPv4Enabled() {
		nodeIPv4 = collectLocalNodeIPs(ifaces, netlink.FAMILY_V4)
	}
	if m.daemonConfig.IPv6Enabled() {
		nodeIPv6 = collectLocalNodeIPs(ifaces, netlink.FAMILY_V6)
	}

	networks := m.networkStore.List()
	nodeIPByNetworkName := make(map[string]nodeIPPair, len(networks))

	for _, network := range networks {
		networkName := network.Name
		if networkName == defaultNetwork {
			continue // for default network we rely on NodeDiscovery
		}

		var nodeIPs nodeIPPair
		for _, route := range network.Spec.Routes {
			_, networkPrefix, err := net.ParseCIDR(string(route.Destination))
			if err != nil {
				log.
					WithFields(logrus.Fields{
						"network":     networkName,
						"destination": route.Destination,
					}).
					Warn("Invalid network route destination. Node IP for this network may not be populated")
				continue
			}

			if networkPrefix.IP.To4() != nil {
				for _, nodeIP := range nodeIPv4 {
					if networkPrefix.Contains(nodeIP) {
						nodeIPs.ipv4 = nodeIP
						break
					}
				}
			} else {
				for _, nodeIP := range nodeIPv6 {
					if networkPrefix.Contains(nodeIP) {
						nodeIPs.ipv6 = nodeIP
						break
					}
				}
			}
		}

		if nodeIPs.ipv4 != nil || nodeIPs.ipv6 != nil {
			nodeIPByNetworkName[networkName] = nodeIPs
		}
	}

	m.mutex.Lock()
	changed := maps.EqualFunc(m.nodeIPByNetworkName, nodeIPByNetworkName, nodeIPPair.Equal)
	m.nodeIPByNetworkName = nodeIPByNetworkName
	m.mutex.Unlock()

	// Make sure changes are reflected in CiliumNode resource
	if changed {
		nodeUpdater.UpdateLocalNode()
	}

	return nil
}
