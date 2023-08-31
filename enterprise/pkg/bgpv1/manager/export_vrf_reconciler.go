// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	bgpv1Types "github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/srv6"
)

type exportVRFReconcilerOut struct {
	cell.Out

	Reconciler manager.ConfigReconciler `group:"bgp-config-reconciler"`
}

type exportVRFReconcilerParams struct {
	cell.In

	Logger      logrus.FieldLogger
	SRv6Manager *srv6.Manager
}

type ExportVRFReconciler struct {
	logger      logrus.FieldLogger
	srv6Manager *srv6.Manager
}

func NewExportVRFReconciler(params exportVRFReconcilerParams) exportVRFReconcilerOut {
	return exportVRFReconcilerOut{
		Reconciler: &ExportVRFReconciler{
			logger:      params.Logger,
			srv6Manager: params.SRv6Manager,
		},
	}
}

func (r *ExportVRFReconciler) Priority() int {
	return 50
}

func (r *ExportVRFReconciler) Reconcile(ctx context.Context, p manager.ReconcileParams) error {
	var (
		toCreate []*srv6.VRF
		toRemove []*types.VPNv4Advertisement
		ipv4Nets []*net.IPNet
		vrfs     []*srv6.VRF
		l        = r.logger.WithFields(
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
			if err := p.CurrentServer.Server.WithdrawPath(ctx, bgpv1Types.PathRequest{Path: path}); err != nil {
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
		advert := types.VPNv4Advertisement{
			VRF: v,
		}
		for _, path := range vpnv4Paths {
			resp, err := p.CurrentServer.Server.AdvertisePath(ctx, bgpv1Types.PathRequest{Path: path})
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
