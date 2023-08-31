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

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/srv6"
)

func mapSRv6EgressPolicy(ctx context.Context, logger logrus.FieldLogger, currentServer *manager.ServerWithConfig, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := logger.WithFields(
		logrus.Fields{
			"component": "manager.srv6.MapSRv6EgressPolicy",
		},
	)
	l.Info("Mapping SRv6 VRFs to SRv6 egress policies.")

	var policies []*srv6.EgressPolicy

	resp, err := currentServer.Server.GetRoutes(ctx, &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv4,
			Safi: types.SafiMplsVpn,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list VPNv4 paths for virtual router with local ASN %d: %w", currentServer.Config.LocalASN, err)
	}

	l.WithField("count", len(resp.Routes)).Info("Discovered advertised VPNv4 routes.")

	for _, r := range resp.Routes {
		for _, p := range r.Paths {
			if p.Best {
				out, err := mapVPNv4ToEgressPolicy(logger, p.PathAttributes, vrfs)
				if err != nil {
					return nil, fmt.Errorf("failed to map VPNv4 paths to egress policies: %w", err)
				}
				policies = append(policies, out...)
			}
		}
	}

	l.WithField("count", len(policies)).Info("Mapped VPNv4 paths to egress policies")

	return policies, nil
}

func mapVRFToVPNv4Paths(podCIDRs []*net.IPNet, vrf *srv6.VRF) ([]*types.Path, error) {
	if vrf.ExportRouteTarget == "" {
		return nil, fmt.Errorf("cannot map VRF without an ExportRouteTarget")
	}

	extComms, err := bgp.ParseRouteTarget(vrf.ExportRouteTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ExportRouteTarget %v into Extended Community: %w", vrf.ExportRouteTarget, err)
	}

	RD, err := bgp.ParseRouteDistinguisher(vrf.ExportRouteTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ExportRouteTarget %v into Route Distinguisher: %w", vrf.ExportRouteTarget, err)
	}

	// Pack ExportRouteTarget into extCommunities attribute
	extCommsAttr := &bgp.PathAttributeExtendedCommunities{
		Value: []bgp.ExtendedCommunityInterface{
			extComms,
		},
	}

	medAttr := bgp.NewPathAttributeMultiExitDisc(0)

	// The SRv6 SID and endpoint behavior is encoded as a set of nested
	// TLVs.
	//
	// The SRv6 TLVs are encoded as a Prefix SID BGP Attribute of type
	// See: https://www.rfc-editor.org/rfc/rfc9252.html#section-4

	// Pack SRv6SIDStructureSubSubTLV details into a SRv6InformationSubTLV
	SIDInfoTLV := &bgp.SRv6InformationSubTLV{
		SID:              vrf.AllocatedSID.To16(),
		EndpointBehavior: uint16(bgp.END_DT4),
		SubSubTLVs: []bgp.PrefixSIDTLVInterface{
			&bgp.SRv6SIDStructureSubSubTLV{
				LocatorBlockLength: 128,
			},
		},
	}

	// Pack SRv6InformationSubTLV into a SRv6L3ServiceAttribute
	L3ServTLV := &bgp.SRv6L3ServiceAttribute{
		SubTLVs: []bgp.PrefixSIDTLVInterface{
			SIDInfoTLV,
		},
	}

	// Encode SRv6L3ServiceAttribute as a PathAttributePrefixSID
	prefixSIDAttr := &bgp.PathAttributePrefixSID{
		TLVs: []bgp.PrefixSIDTLVInterface{
			L3ServTLV,
		},
	}

	// Pack podCIDRs into VPNv4 MP-NLRI
	labeledPrefixes := []bgp.AddrPrefixInterface{}
	for _, podCIDR := range podCIDRs {
		maskLen, _ := podCIDR.Mask.Size()
		vpnv4 := bgp.NewLabeledVPNIPAddrPrefix(uint8(maskLen), podCIDR.IP.String(), *bgp.NewMPLSLabelStack(4096), RD)
		labeledPrefixes = append(labeledPrefixes, vpnv4)
	}
	MpReachAttr := &bgp.PathAttributeMpReachNLRI{
		AFI:     bgp.AFI_IP,
		SAFI:    bgp.SAFI_MPLS_VPN,
		Nexthop: net.ParseIP("0.0.0.0"),
		Value:   labeledPrefixes,
	}

	// Mandatory Attributes, ASPATH will be set by GoBGP directly.
	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)
	nextHop := bgp.NewPathAttributeNextHop("0.0.0.0")

	attrs := []bgp.PathAttributeInterface{
		origin,
		medAttr,
		nextHop,
		extCommsAttr,
		prefixSIDAttr,
		MpReachAttr,
	}

	var paths []*types.Path
	for _, prefix := range labeledPrefixes {
		p := &types.Path{
			NLRI:           prefix,
			PathAttributes: attrs,
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func mapVPNv4ToEgressPolicy(logger logrus.FieldLogger, attrs []bgp.PathAttributeInterface, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := logger.WithFields(
		logrus.Fields{
			"component": "manager.srv6.mapVPNv4ToEgressPolicy",
		},
	)

	var (
		// require extended communities for route target.
		extCommunities *bgp.PathAttributeExtendedCommunities
		// require MP BGP Reach NLRIs to mape prefixes to destination CIDRs
		mpReach *bgp.PathAttributeMpReachNLRI
		// require BGP prefix-sid attribute to extract destination CIDR
		prefixSID *bgp.PathAttributePrefixSID
		// extracted prefixes from MP BGP VPNv4 NLRI
		prefixes []*net.IPNet
		// extracted route target from BGP extended community.
		RT string
		// extracted SRv6 SID from BGP Prefix SID attribute.
		destinationSID [16]byte
	)

	for _, attr := range attrs {
		switch v := attr.(type) {
		case *bgp.PathAttributeExtendedCommunities:
			extCommunities = v
		case *bgp.PathAttributeMpReachNLRI:
			mpReach = v
		case *bgp.PathAttributePrefixSID:
			prefixSID = v
		}
	}

	// if we do not have our required path attributes we cannot map this route.
	// this is not an error.
	if extCommunities == nil {
		l.Debug("Did not find extended communities")
		return nil, nil
	}
	if mpReach == nil {
		l.Debug("Did not find MB NLRIs")
		return nil, nil
	}
	if prefixSID == nil {
		l.Debug("Did not find BGP Prefix SID attribute")
		return nil, nil
	}

	l.Debug("Looking for route target extended community")
	for _, val := range extCommunities.Value {
		switch v := val.(type) {
		case *bgp.FourOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
			}
		case *bgp.TwoOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
			}
		}
	}
	// we did not find a route target.
	if RT == "" {
		l.Debug("Did not find a route target")
		return nil, nil
	}

	// extract our destination CIDRs from MP BGP NLRIs.
	// these will be VPNv4 encoded IPv4 prefixes.
	if (mpReach.SAFI != bgp.SAFI_MPLS_VPN) || (mpReach.AFI != bgp.AFI_IP) {
		// this really shouldn't happen since we do a list for paths of this
		// S/AFI type, but may as well be defensive.
		l.Debug("MB BGP NLRI was not correct S/AFI")
		return nil, nil
	}

	var labels []uint32
	for _, prefix := range mpReach.Value {
		switch v := prefix.(type) {
		case *bgp.LabeledVPNIPAddrPrefix:
			labels = v.Labels.Labels
			mask := net.CIDRMask(int(v.IPPrefixLen()), 32)
			prefixes = append(prefixes, &net.IPNet{
				IP:   v.Prefix,
				Mask: mask,
			})
		}
	}
	if len(prefixes) == 0 {
		l.Debug("No prefixes provided in VPNv4 path")
		return nil, nil
	}

	// first extract SRv6 SID Information Sub-TLV
	// (RFC draft-ietf-bess-srv6-services 3.1) to obtain destination SID.
	//
	// per RFC:
	// When multiple SRv6 SID Information Sub-TLVs are present, the ingress
	// PE SHOULD use the SRv6 SID from the first instance of the Sub-TLV.
	// An implementation MAY provide a local policy to override this
	// selection.
	//
	// we will only utilize the first SID Info Sub-TLV
	unpackL3Serv := func(l3serv *bgp.SRv6L3ServiceAttribute) *bgp.SRv6InformationSubTLV {
		for _, subtlv := range l3serv.SubTLVs {
			switch v := subtlv.(type) {
			case *bgp.SRv6InformationSubTLV:
				return v
			}
		}
		return nil
	}

	// pull out the first occurrence as well, there doesn't seem to be good reason
	// to parse out multiple.
	unpackInfoSubTLV := func(subtlv *bgp.SRv6InformationSubTLV) *bgp.SRv6SIDStructureSubSubTLV {
		var subStructTLV *bgp.SRv6SIDStructureSubSubTLV
		for _, subsubtlv := range subtlv.SubSubTLVs {
			switch v := subsubtlv.(type) {
			case *bgp.SRv6SIDStructureSubSubTLV:
				subStructTLV = v
			}
		}
		return subStructTLV
	}

	for _, tlv := range prefixSID.TLVs {
		switch v := tlv.(type) {
		case *bgp.SRv6L3ServiceAttribute:
			infoSubTLV := unpackL3Serv(v)
			if infoSubTLV == nil {
				continue
			}
			subStructTLV := unpackInfoSubTLV(infoSubTLV)
			if subStructTLV == nil {
				continue
			}
			// per RFC (draft-ietf-bess-srv6-services) if Transposition length
			// is not zero the SID was transposed with an MPLS label.
			if subStructTLV.TranspositionLength != 0 {
				l.Debug("Must transpose MPLS label to obtain SID.")

				if len(labels) == 0 {
					return nil, fmt.Errorf("VPNv4 path expects transposition of SID but no MPLS labels discovered")
				}

				transposed, err := transposeSID(logger, labels[0], infoSubTLV, subStructTLV)
				if err != nil {
					return nil, fmt.Errorf("failed to transpose SID: %w", err)
				}
				copy(destinationSID[:], transposed)
			} else {
				copy(destinationSID[:], infoSubTLV.SID)
			}
		}
	}

	// map into EgressPolicies
	policies := []*srv6.EgressPolicy{}
	for _, vrf := range vrfs {
		if vrf == nil {
			continue
		}
		if vrf.ImportRouteTarget == RT {
			l.Debugf("Matched vrf's route target %v with discovered route target %v", vrf.ImportRouteTarget, RT)
			policy := &srv6.EgressPolicy{
				VRFID:    vrf.VRFID,
				DstCIDRs: prefixes,
				SID:      destinationSID,
			}
			policies = append(policies, policy)
			l.WithField("policy", policy).Debug("Mapped VPNv4 route to policy.")
		}
	}

	return policies, nil
}

// TransposeSID will return a 128 bit array repsenting an SRv6 SID after transposing
// a defined number of bits from the provided MPLS label.
//
// Per RFC: https://datatracker.ietf.org/doc/html/draft-ietf-bess-srv6-services-15#section-4
// When the TranspositionLengh field in the SRv6SIDSubStructureSubSubTLV is greater then 0
// the SRv6 SID must be obtained by transposing a variable bit range from the MPLS label
// within the VPNv4 NLRI. The bit ranges are provided by fields within the SRv6SIDSubStructureSubSubTLV.
func transposeSID(logger logrus.FieldLogger, label uint32, infoTLV *bgp.SRv6InformationSubTLV, structTLV *bgp.SRv6SIDStructureSubSubTLV) ([]byte, error) {
	l := logger.WithFields(
		logrus.Fields{
			"component": "manager.srv6.transposeSID",
		},
	)

	// must shift label by twelve, not sure if this is something with frr or not.
	label = label << 12

	off := structTLV.TranspositionOffset // number of bits into the SID where transposition starts
	le := structTLV.TranspositionLength  // length in bits of transposition
	sid := infoTLV.SID

	l.WithFields(logrus.Fields{
		"label":       fmt.Sprintf("%x", label),
		"offset":      off,
		"length":      le,
		"originalSid": fmt.Sprintf("%x", sid),
		"startByte":   off / 8,
	}).Debug("Starting SID transposition")
	for le > 0 {
		var (
			// current byte index to tranpose
			byteI = off / 8
			// current bit index where bit transposition will occur
			bitI = off % 8
			// number of bits that will be copied from label into sid.
			n = (8 - bitI)
		)
		// get to a byte boundary, then eat full bytes until we can't.
		if le >= 8 {
			mask := ^byte(0) << n
			sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-n)))
			label <<= n
			off = off + n
			le = le - n
			l.WithFields(logrus.Fields{
				"label":          fmt.Sprintf("%x", label),
				"nextOffset":     off,
				"length":         le,
				"copiedN":        n,
				"byteI":          fmt.Sprintf("%x", byteI),
				"bitI":           fmt.Sprintf("%x", bitI),
				"mask":           fmt.Sprintf("%x", mask),
				"transposedByte": fmt.Sprintf("%x", sid[byteI]),
			}).Debug("Transposed bits")
			continue
		}
		// deal with a final bit difference.
		mask := ^byte(0) >> le
		sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-le))) << (8 - le)
		l.WithFields(logrus.Fields{
			"label":          fmt.Sprintf("%x", label),
			"nextOffset":     off,
			"length":         le,
			"copiedN":        n,
			"byteI":          fmt.Sprintf("%x", byteI),
			"bitI":           fmt.Sprintf("%x", bitI),
			"mask":           fmt.Sprintf("%x", mask),
			"transposedByte": fmt.Sprintf("%x", sid[byteI]),
		}).Debug("Transposed bits")
	}
	l.Debugf("Transposed SID %x", sid)
	return sid, nil
}
