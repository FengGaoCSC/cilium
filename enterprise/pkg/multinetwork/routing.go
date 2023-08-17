// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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
	remoteRouteController   = "multi-network-sync-remote-node-routes"
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

type remoteNode struct {
	node   *v2.CiliumNode
	routes []*netlink.Route
}

type remoteNodeRouteManager struct {
	networkStore resource.Store[*iso_v1alpha1.IsovalentPodNetwork]

	mutex lock.Mutex
	nodes map[string]*remoteNode
}

func getNetworkForIPAMPool(networks []*iso_v1alpha1.IsovalentPodNetwork, poolName string) (networkName string, ok bool) {
	for _, network := range networks {
		if network.Spec.IPAM.Pool.Name == poolName {
			return network.Name, true
		}
	}

	return "", false
}

func extractNodeIP(n *nodeTypes.Node, networkName string) (ipv4 net.IP, ipv6 net.IP) {
	// Use the regular node address for the default network
	if networkName == defaultNetwork {
		ipv4 = n.GetNodeIP(false)
		ipv6 = n.GetNodeIP(true)
		return ipv4, ipv6
	}

	// Extract remaining addresses from
	for _, addr := range n.IPAddresses {
		network, ok := extractNetwork(addr.Type)
		if !ok {
			continue
		}

		if network == networkName {
			if addr.IP.To4() != nil {
				ipv4 = addr.IP
			} else {
				ipv6 = addr.IP
			}
		}
	}

	return ipv4, ipv6
}

func createDirectNodeRoute(podCIDR string, nodeIPv4, nodeIPv6 net.IP) (*netlink.Route, error) {
	_, dst, err := net.ParseCIDR(string(podCIDR))
	if err != nil {
		return nil, err
	}

	var gw net.IP
	if dst.IP.To4() != nil {
		gw = nodeIPv4
	} else {
		gw = nodeIPv6
	}

	return &netlink.Route{
		Dst:      dst,
		Gw:       gw,
		Protocol: linux_defaults.RTProto,
	}, nil
}

func extractDirectNodeRoutes(networks []*iso_v1alpha1.IsovalentPodNetwork, node *v2.CiliumNode) (routes []*netlink.Route) {
	if node == nil {
		return nil // return empty slice if node was deleted
	}

	n := nodeTypes.ParseCiliumNode(node)
	for _, pool := range node.Spec.IPAM.Pools.Allocated {
		scopedLog := log.WithFields(logrus.Fields{
			"pool": pool.Pool,
			"node": node.Name,
		})

		poolNetwork, ok := getNetworkForIPAMPool(networks, pool.Pool)
		if !ok {
			scopedLog.Debug("no matching network found for IP pool, skipping")
			continue
		}

		nodeIPv4, nodeIPv6 := extractNodeIP(&n, poolNetwork)
		for _, cidr := range pool.CIDRs {
			route, err := createDirectNodeRoute(string(cidr), nodeIPv4, nodeIPv6)
			if err != nil {
				scopedLog.
					WithField(logfields.CIDR, cidr).
					WithError(err).
					Warn("unable to create direct node route, skipping")
				continue
			}

			routes = append(routes, route)
		}
	}

	return routes
}

func extractRemovedRoutes(oldRoutes, newRoutes []*netlink.Route) (removed []*netlink.Route) {
	for _, oldRoute := range oldRoutes {
		if !slices.ContainsFunc(newRoutes, func(r *netlink.Route) bool {
			return r.Equal(*oldRoute)
		}) {
			removed = append(removed, oldRoute)
		}
	}
	return removed
}

func (m *remoteNodeRouteManager) resyncNodes(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for nodeName, n := range m.nodes {
		m.updateRoutesForNodeLocked(nodeName, n.node, n.routes)
	}

	return nil
}

func (m *remoteNodeRouteManager) updateRoutesForNodeLocked(nodeName string, newNode *v2.CiliumNode, oldRoutes []*netlink.Route) {
	networks := m.networkStore.List()
	newRoutes := extractDirectNodeRoutes(networks, newNode)
	removedRoutes := extractRemovedRoutes(oldRoutes, newRoutes)

	// Remove all obsolete routes
	for _, removedRoute := range removedRoutes {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Route:    removedRoute,
			logfields.NodeName: nodeName,
		})

		scopedLog.Debug("removing direct route")
		if err := netlink.RouteDel(removedRoute); err != nil {
			scopedLog.WithError(err).Warn("Failed to remove node route")
		}
	}

	// Upsert all valid routes. This includes all existing and newly added routes
	for _, upsertRoute := range newRoutes {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Route:    upsertRoute,
			logfields.NodeName: nodeName,
		})

		scopedLog.Debug("upserting direct route")
		if err := netlink.RouteReplace(upsertRoute); err != nil {
			scopedLog.
				WithError(err).
				Warn("Failed to install route for node, traffic to that node will be disrupted")
		}
	}

	// We keep track of installed routes in order to remove them when they or their
	// node is removed. Note that routes can still leak if changes happen while
	// the cilium-agent instance is down.
	m.nodes[nodeName] = &remoteNode{
		node:   newNode,
		routes: newRoutes,
	}
}

func (m *remoteNodeRouteManager) OnUpdateCiliumNode(oldObj, newObj *v2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(newObj) {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	var nodeName string
	if newObj != nil {
		nodeName = newObj.Name
	} else if oldObj != nil {
		nodeName = oldObj.Name
	}

	var oldRoutes []*netlink.Route
	if oldNode, ok := m.nodes[nodeName]; ok {
		oldRoutes = oldNode.routes
	}

	m.updateRoutesForNodeLocked(nodeName, newObj, oldRoutes)

	return nil
}

func (m *remoteNodeRouteManager) OnAddCiliumNode(node *v2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	return m.OnUpdateCiliumNode(nil, node, swg)
}

func (m *remoteNodeRouteManager) OnDeleteCiliumNode(node *v2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	return m.OnUpdateCiliumNode(node, nil, swg)
}
