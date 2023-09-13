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

// newNetworkAddressingType creates a new addressing type for a network.
// The addressing type is part of the Isovalent namespace to avoid clashes with
// upstream addressing types. The addressing type also contains the network name,
// which is used to identify the network of the associated address. We store the
// network name in the type instead of a separate field to avoid having to change
// the upstream (stable) node type.
// This is a temporary solution, the goal is to eventually upstream parts of
// this commit and change the node schema to store the network name.
func newNetworkAddressingType(networkName string) addressing.AddressType {
	return addressing.AddressType(isovalentNetworkIP + ":" + networkName)
}

// extractNetwork extracts the network name from a isovalentNetworkIP addressing type.
func extractNetwork(addressType addressing.AddressType) (networkName string, ok bool) {
	ipType, network, ok := strings.Cut(string(addressType), ":")
	if !ok || ipType != isovalentNetworkIP {
		return "", false
	}

	return network, true
}

// localNetworkIPCollector collects the local node IP addresses for each network
// and updates the local node in K8s or kvstore accordingly. This allows other
// nodes to install direct node routes for secondary networks via the correct IP
// address.

// In multi-homing mode, we now need to assume that a node will have multiple
// node IP addresses, i.e. at least one per network. Therefore, the following
// ccode periodically lists the host's network interfaces and extracts node IP
// addresses based on the route listed in the `IsovalentPodNetwork`.
// If the interface IP matches one of the network's routes, we then assume it is
// the canonical IP address of the node in that network.
// Future extensions and configurations to this mechanism are possible, but for
// now we just support this rather simple mechanism.
//
// The secondary node IPs are then passed to the `NodeDiscovery` package,
// which is responsible for announcing them to other nodes in the kvstore and
// the CiliumNode CRD. This also has the nice side effect that other cilium-agents
// will now add those secondary node IPs into the IPCache with the `remote-node`
// identity.
type localNetworkIPCollector struct {
	daemonConfig daemonConfig

	networkStore resource.Store[*iso_v1alpha1.IsovalentPodNetwork]

	mutex               lock.Mutex // protects nodeIPByNetworkName
	nodeIPByNetworkName map[string]nodeIPPair
}

// GetNodeAddresses returns the local node IP addresses for each discovered network.
// This is invoked by NodeDiscovery to populate the local node resource.
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

// collectLocalNodeIPs collects all local node IP addresses from the given interfaces and IP family.
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

// extractNodeIPsforNetworks extracts the local node IP addresses for each network.
// It does this by matching the network routes to the local node IP addresses. The
// first matching IP address is used for each network.
// It returns a map of network name to node IP pair.
func extractNodeIPsforNetworks(networks []*iso_v1alpha1.IsovalentPodNetwork, nodeIPv4 []net.IP, nodeIPv6 []net.IP) map[string]nodeIPPair {
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
	return nodeIPByNetworkName
}

// updateNodeIPAddresses collects and announces the local node IP
// addresses for each network. By calling nodeUpdater.UpdateLocalNode(), the
// nodeUpdater will call back into GetNodeAddresses() to retrieve the list of
// updated node addresses.
// This is run periodically by the localNodeSyncController controller.
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
	nodeIPByNetworkName := extractNodeIPsforNetworks(networks, nodeIPv4, nodeIPv6)

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

// remoteNode represents a remote node for which we have installed direct node routes
type remoteNode struct {
	node   *v2.CiliumNode
	routes []*netlink.Route
}

// remoteNodeRouteManager manages direct node routes for remote nodes.
//
// Direct node routes are routes in the form of `$podCIDR via $nodeIP` for each
// remote node in the cluster, thereby allowing pod traffic to be routed to the
// connect node on a L2-connected network.
//
// It does this by watching all remote CiliumNodes in the cluster, extracting
// the remote node's multi-pool pod CIDRs, and then installing routes in the
// form of `$podCIDR via $nodeIP` for each node.
//
// Ideally, we would integrate this logic into the existing `auto-direct-node-routes`
// code in upstream. However, because making that code multi-network aware is
// rather intrusive and would require kvstore schema changes, we instead let the
// logic live here in the multinetwork cell for now.
//
// One shortcoming of this (besides code duplication) is that the multinetwork
// version only subscribes to CiliumNode updates, which means clustermesh is
// not supported at the moment.
type remoteNodeRouteManager struct {
	networkStore resource.Store[*iso_v1alpha1.IsovalentPodNetwork]

	mutex lock.Mutex
	nodes map[string]*remoteNode
}

// getNetworkForIPAMPool extracts the network name for the given IPAM pool name
// out of the list of known IsovalentPodNetworks. This each IPAM pool is only used
// in a single network.
func getNetworkForIPAMPool(networks []*iso_v1alpha1.IsovalentPodNetwork, poolName string) (networkName string, ok bool) {
	for _, network := range networks {
		if network.Spec.IPAM.Pool.Name == poolName {
			return network.Name, true
		}
	}

	return "", false
}

// extractNodeIP extracts the node IP for the given network from the given node.
// For the default network, we use the regular node IP also used by other parts
// of non-multi-network aware Cilium. For secondary networks, we extract the
// node IP from isovalentNetworkIP addresses in the IPAddresses field.
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

// createDirectNodeRoute creates a direct node route for the given pod CIDR and
// node IP. The route's next hop will be IPv4 or IPv6 depending on the pod CIDR.
func createDirectNodeRoute(podCIDR string, nodeIPv4, nodeIPv6 net.IP) (*netlink.Route, error) {
	_, dst, err := net.ParseCIDR(podCIDR)
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

// extractDirectNodeRoutes extracts the direct node routes for the given node.
// It does this by matching the node's IPAM pools to the networks and then
// creating a direct node route for each CIDR in the pool. The route's gateway
// will be the node IP for the network of the IPAM pool.
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

			// Skip routes without a gateway. This can happen if the node has not
			// announced its IP address for the pool's network yet
			if route.Gw == nil {
				scopedLog.
					WithField(logfields.CIDR, cidr).
					Debug("no matching node IP found for pod CIDR, skipping")
				continue
			}

			routes = append(routes, route)
		}
	}

	return routes
}

// extractRemovedRoutes extracts the routes that are in oldRoutes but not in newRoutes.
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

// resyncNodes resyncs all direct node routes for all remote nodes. This is
// done periodically for two reasons:
// First, it will reinstall any routes if they got accidentally removed.
// Second, because each route consists of a pod CIDR and a node IP, we re-run
// the route installation logic in case the node IP was only recently discovered.
func (m *remoteNodeRouteManager) resyncNodes(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for nodeName, n := range m.nodes {
		m.updateRoutesForNodeLocked(nodeName, n.node, n.routes)
	}

	return nil
}

// updateRoutesForNodeLocked updates the direct node routes for the given node.
// It does this by extracting the node's direct node routes and then comparing
// them to the previously installed routes. It then removes all routes that are
// not in the new set of extracted routes and re-installs all routes, including
// the ones in oldRoutes to ensure they were not accidentally removed.
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

// OnUpdateCiliumNode is called when a remote CiliumNode is updated. In this case,
// we want to update the direct node routes for the node.
func (m *remoteNodeRouteManager) OnUpdateCiliumNode(oldObj, newObj *v2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(oldObj) || k8s.IsLocalCiliumNode(newObj) {
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
