// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policymetadata

import (
	"errors"
	"net/netip"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

type endpointPolicyGetter interface {
	GetRealizedPolicyRuleLabelsForKey(key policy.Key) (derivedFrom labels.LabelArrayList, revision uint64, ok bool)
}

func extractFlowKey(f *pb.Flow) (
	direction trafficdirection.TrafficDirection,
	endpointIP netip.Addr,
	remoteIdentity identity.NumericIdentity,
	proto u8proto.U8proto,
	dport uint16) {

	switch f.GetTrafficDirection() {
	case pb.TrafficDirection_EGRESS:
		direction = trafficdirection.Egress
		endpointIP, _ = netip.ParseAddr(f.GetIP().GetSource())
		remoteIdentity = identity.NumericIdentity(f.GetDestination().GetIdentity())
	case pb.TrafficDirection_INGRESS:
		direction = trafficdirection.Ingress
		endpointIP, _ = netip.ParseAddr(f.GetIP().GetDestination())
		remoteIdentity = identity.NumericIdentity(f.GetSource().GetIdentity())
	default:
		direction = trafficdirection.Invalid
		endpointIP = netip.IPv4Unspecified()
		remoteIdentity = identity.IdentityUnknown
	}

	if tcp := f.GetL4().GetTCP(); tcp != nil {
		proto = u8proto.TCP
		dport = uint16(tcp.GetDestinationPort())
	} else if udp := f.GetL4().GetUDP(); udp != nil {
		proto = u8proto.UDP
		dport = uint16(udp.GetDestinationPort())
	} else {
		proto = u8proto.ANY
		dport = 0
	}

	return
}

func lookupPolicyForKey(ep endpointPolicyGetter, key policy.Key) (derivedFrom labels.LabelArrayList, rev uint64, ok bool) {
	// Check for L4 policy rules
	derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(key)

	// TODO: We should inspect f.GetPolicyMatchType() to reduce the number of lookups here
	if !ok {
		// Check for L3 policy rules
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
			Identity:         key.Identity,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: key.TrafficDirection,
		})
	}

	if !ok {
		// Check for allow-all policy rules
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: key.TrafficDirection,
		})
	}

	return derivedFrom, rev, ok
}

func toProto(derivedFrom labels.LabelArrayList, rev uint64) (policies []*pb.Policy) {
	for i, lbl := range derivedFrom {
		// derivedFrom may contain a duplicate policies if the policy had
		// multiple that contributed to the same policy map entry.
		// We can easily detect the duplicates here, because derivedFrom is
		// sorted.
		if i > 0 && lbl.Equals(derivedFrom[i-1]) {
			continue
		}

		policy := &pb.Policy{
			Labels:   lbl.GetModel(),
			Revision: rev,
		}

		var ns, name string
		for _, l := range lbl {
			if l.Source == string(source.Kubernetes) {
				switch l.Key {
				case k8sConst.PolicyLabelName:
					name = l.Value
				case k8sConst.PolicyLabelNamespace:
					ns = l.Value
				}
			}

			if name != "" && ns != "" {
				policy.Name = name
				policy.Namespace = ns
				break
			}
		}

		policies = append(policies, policy)
	}

	return policies
}

func (p *policyCorrelation) correlatePolicy(f *pb.Flow) error {
	if f.GetEventType().GetType() != int32(monitorAPI.MessageTypePolicyVerdict) ||
		f.GetVerdict() != pb.Verdict_FORWARDED {
		// we are only interested in policy verdict notifications for forwarded flows
		return nil
	}

	// extract fields relevant for looking up the policy
	direction, endpointIP, remoteIdentity, proto, dport := extractFlowKey(f)

	// obtain reference to endpoint on which the policy verdict was taken
	epInfo, ok := p.endpointGetter.GetEndpointInfo(endpointIP)
	if !ok {
		logger.WithField(logfields.IPAddr, endpointIP).Debug("dropping policy verdict notification for unknown endpoint")
		return nil
	}
	ep, ok := epInfo.(endpointPolicyGetter)
	if !ok {
		// cilium endpoint does not implement GetRealizedPolicyRuleLabelsForKey
		return errors.New("unsupported cilium version")
	}

	derivedFrom, rev, ok := lookupPolicyForKey(ep, policy.Key{
		Identity:         uint32(remoteIdentity),
		DestPort:         dport,
		Nexthdr:          uint8(proto),
		TrafficDirection: uint8(direction),
	})
	if !ok {
		logger.WithFields(logrus.Fields{
			logfields.Identity:         remoteIdentity,
			logfields.Port:             dport,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		}).Debug("unable to find policy for policy verdict notification")
		return nil
	}

	allowedBy := toProto(derivedFrom, rev)
	switch direction {
	case trafficdirection.Egress:
		f.EgressAllowedBy = allowedBy
	case trafficdirection.Ingress:
		f.IngressAllowedBy = allowedBy
	}

	return nil
}
