// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
)

// EgressPolicy is the internal representation of CiliumSRv6EgressPolicy.
type EgressPolicy struct {
	// id is the parsed policy name and namespace
	id types.NamespacedName

	VRFID    uint32
	DstCIDRs []*net.IPNet
	SID      ciliumTypes.IPv6
}

// deepcopy-gen cannot generate a DeepCopyInto for net.IPNet. Define by ourselves.
func (in *EgressPolicy) DeepCopy() *EgressPolicy {
	if in == nil {
		return nil
	}
	out := new(EgressPolicy)
	in.DeepCopyInto(out)
	return out
}

func (in *EgressPolicy) DeepCopyInto(out *EgressPolicy) {
	out.id = in.id
	out.VRFID = in.VRFID
	out.DstCIDRs = make([]*net.IPNet, len(in.DstCIDRs))
	for i, cidr := range in.DstCIDRs {
		out.DstCIDRs[i] = &net.IPNet{
			IP:   make(net.IP, len(cidr.IP)),
			Mask: make(net.IPMask, len(cidr.Mask)),
		}
		copy(out.DstCIDRs[i].IP, cidr.IP)
		copy(out.DstCIDRs[i].Mask, cidr.Mask)
	}
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

func ParsePolicy(csrep *v2alpha1.CiliumSRv6EgressPolicy) (*EgressPolicy, error) {
	var dstCidrList []*net.IPNet
	var sid ciliumTypes.IPv6

	name := csrep.ObjectMeta.Name

	if name == "" {
		return nil, fmt.Errorf("CiliumSRv6EgressPolicy must have a name")
	}

	copy(sid[:], net.ParseIP(csrep.Spec.DestinationSID).To16())

	for _, cidrString := range csrep.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumSRv6EgressPolicyName: name}).Warn("Error parsing CIDR.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	return &EgressPolicy{
		id: types.NamespacedName{
			Name: name,
		},
		VRFID:    csrep.Spec.VRFID,
		DstCIDRs: dstCidrList,
		SID:      sid,
	}, nil
}

// ParseEgressPolicyID takes a CiliumSRv6EgressPolicy CR and returns only the policy id
func ParseEgressPolicyID(csrep *v2alpha1.CiliumSRv6EgressPolicy) types.NamespacedName {
	return policyID{
		Name: csrep.Name,
	}
}
