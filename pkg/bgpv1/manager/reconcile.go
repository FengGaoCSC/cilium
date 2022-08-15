// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	ciliumslices "github.com/cilium/cilium/pkg/slices"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	srv6 "github.com/cilium/cilium/pkg/srv6"
)

type ReconcileParams struct {
	CurrentServer *ServerWithConfig
	DesiredConfig *v2alpha1api.CiliumBGPVirtualRouter
	Node          *node.LocalNode
}

// ConfigReconciler is a interface for reconciling a particular aspect
// of an old and new *v2alpha1api.CiliumBGPVirtualRouter
type ConfigReconciler interface {
	// Priority is used to determine the order in which reconcilers are called. Reconcilers are called from lowest to
	// highest.
	Priority() int
	// Reconcile If the `Config` field in `params.sc` is nil the reconciler should unconditionally
	// perform the reconciliation actions, as no previous configuration is present.
	Reconcile(ctx context.Context, params ReconcileParams) error
}

var ConfigReconcilers = cell.ProvidePrivate(
	NewPreflightReconciler,
	NewNeighborReconciler,
	NewExportPodCIDRReconciler,
	NewLBServiceReconciler,
	NewExportVRFReconciler,
	NewImportVRFReconciler,
)

type PreflightReconcilerParams struct {
	cell.In
	BGPCPSignaler *signaler.BGPCPSignaler
}

type PreflightReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// PreflightReconciler is a preflight task before any other reconciliation should
// take place.
//
// this reconciler handles any changes in current and desired BgpState which leads
// to a recreation of an existing BgpServer.
//
// this must be done first so that the following reconciliation functions act
// upon the recreated BgpServer with the desired permanent configurations.
//
// permanent configurations for BgpServers (ones that cannot be changed after creation)
// are router ID and local listening port.
type PreflightReconciler struct {
	signaler *signaler.BGPCPSignaler
}

func NewPreflightReconciler(params PreflightReconcilerParams) PreflightReconcilerOut {
	return PreflightReconcilerOut{
		Reconciler: &PreflightReconciler{
			signaler: params.BGPCPSignaler,
		},
	}
}

func (r *PreflightReconciler) Priority() int {
	return 10
}

func (r *PreflightReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "manager.preflightReconciler",
			},
		)
	)

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this server is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if p.CurrentServer.Config == nil {
		l.Debugf("Preflight for virtual router with ASN %v not necessary, first instantiation of this BgpServer.", p.DesiredConfig.LocalASN)
		return nil
	}

	l.Debugf("Begin preflight reoncilation for virtual router with ASN %v", p.DesiredConfig.LocalASN)
	bgpInfo, err := p.CurrentServer.Server.GetBGP(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.Node.Annotations)
	if err != nil {
		return fmt.Errorf("failed to parse Node annotations for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := annoMap[p.DesiredConfig.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	routerID, err := annoMap.ResolveRouterID(p.DesiredConfig.LocalASN)
	if err != nil {
		nodeIP := p.Node.GetNodeIP(false)
		if nodeIP.IsUnspecified() {
			return fmt.Errorf("failed to resolve router id")
		}
		routerID = nodeIP.String()
	}

	var shouldRecreate bool
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v local port has changed from %v to %v", p.DesiredConfig.LocalASN, bgpInfo.Global.ListenPort, localPort)
	}
	if routerID != bgpInfo.Global.RouterID {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v router ID has changed from %v to %v", p.DesiredConfig.LocalASN, bgpInfo.Global.RouterID, routerID)
	}
	if !shouldRecreate {
		l.Debugf("No preflight reconciliation necessary for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
		return nil
	}

	l.Infof("Recreating virtual router with ASN %v for changes to take effect", p.DesiredConfig.LocalASN)
	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(p.DesiredConfig.LocalASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
		OnFIBEvent: func() {
			if r.signaler != nil {
				r.signaler.Event(struct{}{})
			}
		},
	}

	// stop the old BgpServer
	p.CurrentServer.Server.Stop()

	// create a new one via ServerWithConfig constructor
	s, err := NewServerWithConfig(ctx, globalConfig)
	if err != nil {
		l.WithError(err).Errorf("Failed to start BGP server for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
		return fmt.Errorf("failed to start BGP server for virtual router with local ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// replace the old underlying server with our recreated one
	p.CurrentServer.Server = s.Server

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new BgpServer.
	p.CurrentServer.Config = nil

	// Clear the shadow state since any advertisements will be gone now that the server has been recreated.
	p.CurrentServer.PodCIDRAnnouncements = nil
	p.CurrentServer.ServiceAnnouncements = make(map[resource.Key][]*types.Path)

	return nil
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// neighborReconciler is a ConfigReconcilerFunc which reconciles the peers of
// the provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct{}

func NewNeighborReconciler() NeighborReconcilerOut {
	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{},
	}
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return 60
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "manager.neighborReconciler",
			},
		)
		toCreate []*v2alpha1api.CiliumBGPNeighbor
		toRemove []*v2alpha1api.CiliumBGPNeighbor
		toUpdate []*v2alpha1api.CiliumBGPNeighbor
		curNeigh []v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := p.DesiredConfig.Neighbors
	l.Debugf("Begin reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)

	// sc.Config can be nil if there is no previous configuration.
	if p.CurrentServer.Config != nil {
		curNeigh = p.CurrentServer.Config.Neighbors
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		new *v2alpha1api.CiliumBGPNeighbor
		cur *v2alpha1api.CiliumBGPNeighbor
	}

	nset := map[string]*member{}

	// populate set from universe of new neighbors
	for i, n := range newNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &newNeigh[i],
			}
			continue
		}
		h.new = &newNeigh[i]
	}

	// populate set from universe of current neighbors
	for i, n := range curNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: &curNeigh[i],
			}
			continue
		}
		h.cur = &curNeigh[i]
	}

	for _, m := range nset {
		// present in new neighbors (set new) but not in current neighbors (set cur)
		if m.new != nil && m.cur == nil {
			toCreate = append(toCreate, m.new)
		}
		// present in current neighbors (set cur) but not in new neighbors (set new)
		if m.cur != nil && m.new == nil {
			toRemove = append(toRemove, m.cur)
		}
		// present in both new neighbors (set new) and current neighbors (set cur), update if they are not equal
		if m.cur != nil && m.new != nil {
			if !m.cur.DeepEqual(m.new) {
				toUpdate = append(toUpdate, m.new)
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Infof("Reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	} else {
		l.Debugf("No peer changes necessary for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Infof("Adding peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.AddNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Infof("Updating peer %v %v in local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.UpdateNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v from local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.RemoveNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	l.Infof("Done reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	return nil
}

type ExportPodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// exportPodCIDRReconciler is a ConfigReconcilerFunc which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
type ExportPodCIDRReconciler struct{}

func NewExportPodCIDRReconciler() ExportPodCIDRReconcilerOut {
	return ExportPodCIDRReconcilerOut{
		Reconciler: &ExportPodCIDRReconciler{},
	}
}

func (r *ExportPodCIDRReconciler) Priority() int {
	return 30
}

func (r *ExportPodCIDRReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil ServerWithConfig")
	}
	if p.Node == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil LocalNode")
	}

	var toAdvertise []*types.Path
	for _, cidr := range p.Node.ToCiliumNode().Spec.IPAM.PodCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse prefix %s: %w", cidr, err)
		}
		toAdvertise = append(toAdvertise, types.NewPathForPrefix(prefix))
	}

	advertisements, err := exportAdvertisementsReconciler(&advertisementsReconcilerParams{
		ctx:       ctx,
		name:      "pod CIDR",
		component: "manager.exportPodCIDRReconciler",
		enabled:   *p.DesiredConfig.ExportPodCIDR,

		sc:   p.CurrentServer,
		newc: p.DesiredConfig,

		currentAdvertisements: p.CurrentServer.PodCIDRAnnouncements,
		toAdvertise:           toAdvertise,
	})

	if err != nil {
		return err
	}

	// Update the server config's list of current advertisements only if the
	// reconciliation logic didn't return any error
	p.CurrentServer.PodCIDRAnnouncements = advertisements
	return nil
}

type LBServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type LBServiceReconciler struct {
	diffStore   DiffStore[*slim_corev1.Service]
	epDiffStore DiffStore[*k8s.Endpoints]
}

type localServices map[k8s.ServiceID]struct{}

func NewLBServiceReconciler(diffStore DiffStore[*slim_corev1.Service], epDiffStore DiffStore[*k8s.Endpoints]) LBServiceReconcilerOut {
	if diffStore == nil {
		return LBServiceReconcilerOut{}
	}

	return LBServiceReconcilerOut{
		Reconciler: &LBServiceReconciler{
			diffStore:   diffStore,
			epDiffStore: epDiffStore,
		},
	}
}

func (r *LBServiceReconciler) Priority() int {
	return 40
}

func (r *LBServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.Node == nil {
		return fmt.Errorf("nil LocalNode")
	}

	var existingSelector *slim_metav1.LabelSelector
	if p.CurrentServer != nil && p.CurrentServer.Config != nil {
		existingSelector = p.CurrentServer.Config.ServiceSelector
	}

	ls := r.populateLocalServices(p.Node.Name)

	// If the existing selector was updated, went from nil to something or something to nil, we need to perform full
	// reconciliation and check if every existing announcement's service still matches the selector.
	changed := (existingSelector != nil && p.DesiredConfig.ServiceSelector != nil && !p.DesiredConfig.ServiceSelector.DeepEqual(existingSelector)) ||
		((existingSelector == nil) != (p.DesiredConfig.ServiceSelector == nil))

	if changed {
		if err := r.fullReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls); err != nil {
			return fmt.Errorf("full reconciliation: %w", err)
		}

		return nil
	}

	if err := r.svcDiffReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls); err != nil {
		return fmt.Errorf("svc Diff reconciliation: %w", err)
	}

	return nil
}

func (r *LBServiceReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceID.Name,
		Namespace: eps.ServiceID.Namespace,
	}
	return r.diffStore.GetByKey(k)
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *LBServiceReconciler) populateLocalServices(localNodeName string) localServices {
	ls := make(localServices)

endpointsLoop:
	for _, eps := range r.epDiffStore.List() {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from endpoints. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local
		if svc.Spec.ExternalTrafficPolicy != slim_corev1.ServiceExternalTrafficPolicyLocal {
			continue
		}

		svcID := eps.ServiceID

		for _, be := range eps.Backends {
			if be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can make unavailable to available.
				if _, found := ls[svcID]; !found {
					ls[svcID] = struct{}{}
				}
				continue endpointsLoop
			}
		}
	}

	return ls
}

func hasLocalEndpoints(svc *slim_corev1.Service, ls localServices) bool {
	_, found := ls[k8s.ServiceID{Name: svc.GetName(), Namespace: svc.GetNamespace()}]
	return found
}

// fullReconciliation reconciles all services, this is a heavy operation due to the potential amount of services and
// thus should be avoided if partial reconciliation is an option.
func (r *LBServiceReconciler) fullReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	// Loop over all existing announcements, delete announcements for services which no longer exist
	for svcKey := range sc.ServiceAnnouncements {
		_, found, err := r.diffStore.GetByKey(svcKey)
		if err != nil {
			return fmt.Errorf("diffStore.GetByKey(); %w", err)
		}
		// if the service no longer exists, withdraw all associated routes
		if !found {
			if err := r.withdrawService(ctx, sc, svcKey); err != nil {
				return fmt.Errorf("withdrawService(): %w", err)
			}
			continue
		}
	}

	// Loop over all services, reconcile any updates to the service
	iter := r.diffStore.IterKeys()
	for iter.Next() {
		svcKey := iter.Key()
		svc, found, err := r.diffStore.GetByKey(iter.Key())
		if err != nil {
			return fmt.Errorf("diffStore.GetByKey(); %w", err)
		}
		if !found {
			// edgecase: If the service was removed between the call to IterKeys() and GetByKey()
			if err := r.withdrawService(ctx, sc, svcKey); err != nil {
				return fmt.Errorf("withdrawService(): %w", err)
			}
			continue
		}

		r.reconcileService(ctx, sc, newc, svc, ls)
	}
	return nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted since
// the last diff reconciliation.
func (r *LBServiceReconciler) svcDiffReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	upserted, deleted, err := r.diffStore.Diff()
	if err != nil {
		return fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the endpoints and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff()
	if err != nil {
		return fmt.Errorf("endpoints store diff: %w", err)
	}

	for _, eps := range epsUpserted {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from endpoints. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local
		if svc.Spec.ExternalTrafficPolicy != slim_corev1.ServiceExternalTrafficPolicyLocal {
			continue
		}

		upserted = append(upserted, svc)
	}

	// We may have duplicated services that changes happened for both of
	// service and associated endpoints.
	deduped := ciliumslices.UniqueFunc(
		upserted,
		func(i int) resource.Key {
			return resource.Key{
				Name:      upserted[i].GetName(),
				Namespace: upserted[i].GetNamespace(),
			}
		},
	)

	for _, svc := range deduped {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("reconcile service: %w", err)
		}
	}

	// Loop over the deleted services
	for _, svcKey := range deleted {
		if err := r.withdrawService(ctx, sc, svcKey); err != nil {
			return fmt.Errorf("withdrawService(): %w", err)
		}
	}

	return nil
}

// svcDesiredRoutes determines which, if any routes should be announced for the given service. This determines the
// desired state.
func (r *LBServiceReconciler) svcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) ([]netip.Prefix, error) {
	if newc.ServiceSelector == nil {
		// If the vRouter has no service selector, there are no desired routes.
		return nil, nil
	}

	// Ignore non-loadbalancer services.
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return nil, nil
	}

	// The vRouter has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(newc.ServiceSelector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services.
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2alpha1api.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return nil, nil
	}

	// Ignore externalTrafficPolicy == Local && no local endpoints.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		addr, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}

		desiredRoutes = append(desiredRoutes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return desiredRoutes, err
}

// reconcileService gets the desired routes of a given service and makes sure that is what is being announced.
// Adding missing announcements or withdrawing unwanted ones.
func (r *LBServiceReconciler) reconcileService(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) error {
	svcKey := resource.NewKey(svc)

	desiredCidrs, err := r.svcDesiredRoutes(newc, svc, ls)
	if err != nil {
		return fmt.Errorf("svcDesiredRoutes(): %w", err)
	}

	for _, desiredCidr := range desiredCidrs {
		// If this route has already been announced, don't add it again
		if slices.IndexFunc(sc.ServiceAnnouncements[svcKey], func(existing *types.Path) bool {
			return desiredCidr.String() == existing.NLRI.String()
		}) != -1 {
			continue
		}

		// Advertise the new cidr
		advertPathResp, err := sc.Server.AdvertisePath(ctx, types.PathRequest{
			Path: types.NewPathForPrefix(desiredCidr),
		})
		if err != nil {
			return fmt.Errorf("failed to advertise service route %v: %w", desiredCidr, err)
		}
		sc.ServiceAnnouncements[svcKey] = append(sc.ServiceAnnouncements[svcKey], advertPathResp.Path)
	}

	// Loop over announcements in reverse order so we can delete entries without effecting iteration.
	for i := len(sc.ServiceAnnouncements[svcKey]) - 1; i >= 0; i-- {
		announcement := sc.ServiceAnnouncements[svcKey][i]
		// If the announcement is within the list of desired routes, don't remove it
		if slices.IndexFunc(desiredCidrs, func(existing netip.Prefix) bool {
			return existing.String() == announcement.NLRI.String()
		}) != -1 {
			continue
		}

		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: announcement}); err != nil {
			return fmt.Errorf("failed to withdraw service route %s: %w", announcement.NLRI, err)
		}

		// Delete announcement from slice
		sc.ServiceAnnouncements[svcKey] = slices.Delete(sc.ServiceAnnouncements[svcKey], i, i+1)
	}

	return nil
}

// withdrawService removes all announcements for the given service
func (r *LBServiceReconciler) withdrawService(ctx context.Context, sc *ServerWithConfig, key resource.Key) error {
	advertisements := sc.ServiceAnnouncements[key]
	// Loop in reverse order so we can delete without effect to the iteration.
	for i := len(advertisements) - 1; i >= 0; i-- {
		advertisement := advertisements[i]
		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: advertisement}); err != nil {
			// Persist remaining advertisements
			sc.ServiceAnnouncements[key] = advertisements
			return fmt.Errorf("failed to withdraw deleted service route: %v: %w", advertisement.NLRI, err)
		}

		// Delete the advertisement after each withdraw in case we error half way through
		advertisements = slices.Delete(advertisements, i, i+1)
	}

	// If all were withdrawn without error, we can delete the whole svc from the map
	delete(sc.ServiceAnnouncements, key)

	return nil
}

func serviceLabelSet(svc *slim_corev1.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels)
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name
	svcLabels["io.kubernetes.service.namespace"] = svc.Namespace
	return labels.Set(svcLabels)
}

type exportVRFReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type exportVRFReconcilerParams struct {
	cell.In

	SRv6Manager *srv6.Manager
}

type ExportVRFReconciler struct {
	srv6Manager *srv6.Manager
}

func NewExportVRFReconciler(params exportVRFReconcilerParams) exportVRFReconcilerOut {
	return exportVRFReconcilerOut{
		Reconciler: &ExportVRFReconciler{
			srv6Manager: params.SRv6Manager,
		},
	}
}

func (r *ExportVRFReconciler) Priority() int {
	return 50
}

// VPNv4Advertisement is a container object which associates a VRF information and VPNv4 Prefixes
//
// The Path field is the advertised path object which can be forwarded to BGP server's
// WithdrawPath method, making withdrawing an advertised route simple.
type VPNv4Advertisement struct {
	VRF   *srv6.VRF
	Paths []*types.Path
}

func (r *ExportVRFReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	var (
		toCreate []*srv6.VRF
		toRemove []*VPNv4Advertisement
		ipv4Nets []*net.IPNet
		vrfs     []*srv6.VRF
		l        = log.WithFields(
			logrus.Fields{
				"component": "manager.reconcileExportedVRFs",
			},
		)
	)

	if r.srv6Manager == nil {
		l.Info("SRv6 sub-system is not enabled, performing no action.")
		return nil
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.Node.Annotations)
	if err != nil {
		return fmt.Errorf("failed to parse Node annotations for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}
	if !annoMap[p.DesiredConfig.LocalASN].SRv6Responder {
		l.Infof("Node %s is not an SRv6 Responder, will not write CiliumSRv6EgressPolicy CRDs to cluster.", p.Node.Name)
		return nil
	}

	// collect VRFs from SRv6Manager.
	vrfs = r.srv6Manager.GetAllVRFs()

	// collect PodCIDR IPv4 addresses to export.
	for _, cidr := range p.Node.ToCiliumNode().Spec.IPAM.PodCIDRs {
		i, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse provided podCIDR string into IPNet")
		}
		if i.To4() == nil {
			continue
		}
		ipv4Nets = append(ipv4Nets, net)
	}

	// record which Advertisements we need to remove since their VRF Export Route
	// target has changed, or they do not exist.
	for _, advert := range p.CurrentServer.SRv6L3VPNAnnouncements {
		shouldRemove := true
		for _, v := range vrfs {
			if (advert.VRF.VRFID == v.VRFID) && (advert.VRF.ExportRouteTarget == v.ExportRouteTarget) {
				shouldRemove = false
				break
			}
		}
		if shouldRemove {
			toRemove = append(toRemove, &advert)
		}
	}

	for _, v := range vrfs {
		// determine if this sc has an advertisement for the provided VRF.
		advert, ok := p.CurrentServer.SRv6L3VPNAnnouncements[v.VRFID]
		if ok {
			// if we have an advert, but the incoming VRF has a different
			// ExportRouteTarget, mark it as create.
			if v.ExportRouteTarget != advert.VRF.ExportRouteTarget {
				toCreate = append(toCreate, v)
			}
			continue
		}
		toCreate = append(toCreate, v)
	}

	l.WithFields(logrus.Fields{
		"toRemove": len(toRemove),
		"toCreate": len(toCreate),
	}).Info("Reconciling VPNv4 Advertisements")

	// remove no longer exists advertisements
	for _, advert := range toRemove {
		for _, path := range advert.Paths {
			if err := p.CurrentServer.Server.WithdrawPath(ctx, types.PathRequest{Path: path}); err != nil {
				l.WithField("vrfID", advert.VRF.VRFID).WithError(err).
					Error("Failed remove advertised VRF VPNv4 route.")
			}
		}
		delete(p.CurrentServer.SRv6L3VPNAnnouncements, advert.VRF.VRFID)
	}

	// create necessary advertisement.
	for _, v := range toCreate {
		vpnv4Paths, err := mapVRFToVPNv4Paths(ipv4Nets, v)
		if err != nil {
			l.WithField("vrfID", v.VRFID).WithError(err).Error("Failed map VRF VPNv4 paths.")
			continue
		}
		advert := VPNv4Advertisement{
			VRF: v,
		}
		for _, path := range vpnv4Paths {
			resp, err := p.CurrentServer.Server.AdvertisePath(ctx, types.PathRequest{Path: path})
			if err != nil {
				l.WithField("vrfID", v.VRFID).WithError(err).Error("Failed advertise VRF VPNv4 path.")
				continue
			}
			advert.Paths = append(advert.Paths, resp.Path)
			l.WithField("vrfID", v.VRFID).Infof("Advertised VRF VPNv4 path %s.", resp.Path.NLRI)
		}
		p.CurrentServer.SRv6L3VPNAnnouncements[advert.VRF.VRFID] = advert
	}

	return nil
}

type importedVRFReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type importedVRFReconcilerParams struct {
	cell.In

	SRv6Manager    *srv6.Manager
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	Clientset      client.Clientset
}

type ImportedVRFReconciler struct {
	srv6Manager *srv6.Manager
	policies    resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	clientset   client.Clientset
}

func NewImportVRFReconciler(params importedVRFReconcilerParams) importedVRFReconcilerOut {
	return importedVRFReconcilerOut{
		Reconciler: &ImportedVRFReconciler{
			srv6Manager: params.SRv6Manager,
			policies:    params.PolicyResource,
			clientset:   params.Clientset,
		},
	}
}

func (r *ImportedVRFReconciler) Priority() int {
	return 50
}

func (r *ImportedVRFReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "manager.reconcileImportedVRFs",
			},
		)
		toCreate []*srv6.EgressPolicy
		toRemove []*srv6.EgressPolicy
	)

	if !p.DesiredConfig.MapSRv6VRFs {
		l.Infof("VRouter %d will not map learned VPNv4 routes.", p.DesiredConfig.LocalASN)
		return nil
	}

	vrfs := r.srv6Manager.GetAllVRFs()

	curPolicies := r.srv6Manager.GetEgressPolicies()
	l.WithField("count", len(curPolicies)).Debug("Discovered current egress policies")

	newPolicies, err := mapSRv6EgressPolicy(ctx, p.CurrentServer, vrfs)
	if err != nil {
		return fmt.Errorf("failed to map VRFs into SRv6 egress policies: %w", err)
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		// present in new policies universe
		a bool
		// present in current policies universe
		b bool
		p *srv6.EgressPolicy
	}

	// set of unique policies
	pset := map[string]*member{}

	// evaluate new policies
	for i, p := range newPolicies {

		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				a: true,
				p: newPolicies[i],
			}
			continue
		}
		h.a = true
	}
	// evaluate current policies
	for i, p := range curPolicies {
		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				b: true,
				p: curPolicies[i],
			}
			continue
		}
		h.b = true
	}

	for _, m := range pset {
		// present in new policies but not in current, create
		if m.a && !m.b {
			toCreate = append(toCreate, m.p)
		}
		// present in current policies but not new, remove.
		if m.b && !m.a {
			toRemove = append(toRemove, m.p)
		}
	}
	l.WithField("count", len(toCreate)).Info("Number of SRv6 egress policies to create.")
	l.WithField("count", len(toRemove)).Info("Number of SRv6 egress policies to remove.")

	clientSet := r.clientset.CiliumV2alpha1().CiliumSRv6EgressPolicies()

	mkName := func(p *srv6.EgressPolicy) (string, error) {
		const prefix = "bgp-control-plane"

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%s-%s", prefix, key), nil
	}

	var name string

	for _, p := range toCreate {
		destCIDRs := []v2alpha1api.CIDR{}
		for _, c := range p.DstCIDRs {
			destCIDRs = append(destCIDRs, v2alpha1api.CIDR(c.String()))
		}

		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		egressPol := &v2alpha1api.CiliumSRv6EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2alpha1",
				Kind:       "CiliumSRv6EgressPolicy",
			},
			Spec: v2alpha1api.CiliumSRv6EgressPolicySpec{
				VRFID:            p.VRFID,
				DestinationCIDRs: []v2alpha1api.CIDR(destCIDRs),
				DestinationSID:   p.SID.IP().String(),
			},
		}
		l.WithField("policy", egressPol).Debug("Writing egress policy to Kubernetes")
		res, err := clientSet.Create(ctx, egressPol, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to write egress policy to Kubernetes: %w", err)
		}
		l.WithField("policy", res).Debug("Resulting egress policy")
	}

	for _, p := range toRemove {
		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		l.WithField("policy", p).Debug("Removing egress policy from Kubernetes")
		err := clientSet.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to remove egress policy: %w", err)
		}
	}

	return nil
}

// keyifySRv6Policy creates a string key for a SRv6PolicyConfig.
func keyifySRv6Policy(p *srv6.EgressPolicy) (string, error) {
	b := &bytes.Buffer{}

	id := strconv.FormatUint(uint64(p.VRFID), 10)
	if _, err := b.Write([]byte(id)); err != nil {
		return "", err
	}

	for _, cidr := range p.DstCIDRs {
		if _, err := b.Write([]byte(cidr.String())); err != nil {
			return "", err
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
