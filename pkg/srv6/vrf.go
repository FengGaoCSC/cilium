// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// VRF is the internal representation of CiliumSRv6VRF.
// +k8s:deepcopy-gen=true
type VRF struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	// Those two fields are exposed to the BGP manager can deduce which BGP
	// route should be installed in which VRF.
	VRFID             uint32
	ImportRouteTarget string
	ExportRouteTarget string

	// SID allocation information
	LocatorPool string
	SIDInfo     *sidmanager.SIDInfo

	rules []VRFRule
}

// getVRFKeysFromMatchingEndpoint will iterate over this VRF's rule set, searching for
// any matching endpoints within the `endpoints` argument.
//
// if a provided endpoint matches a rule a srv6map.VRFKey will be created for
// each of the endpoint's IPv6 addresses and appended to the returned slice.
func (m *Manager) getVRFKeysFromMatchingEndpoint(vrf *VRF) []srv6map.VRFKey {
	logger := log.WithFields(logrus.Fields{
		logfields.VRF: vrf.id,
	})
	keys := []srv6map.VRFKey{}
	for _, rule := range vrf.rules {
		for _, endpoint := range m.cepStore.List() {
			// NOTE: endpoint.Labels is always nil, as labels are not stored in the slim CiliumEndpoint.
			// Because of that, we need to retrieve them based on the endpoint identity.
			// We could use endpoint.Identity.Labels right away, but that would require parsing them,
			// - so we retrieve them from the identityCache.IdentityAllocator instead (getIdentityLabels).
			if endpoint.Identity == nil {
				logger.WithFields(logrus.Fields{logfields.K8sEndpointName: endpoint.Name, logfields.K8sNamespace: endpoint.Namespace}).
					Warning("Endpoint does not have an identity, skipping from VRF matching")
				continue
			}
			labels, err := m.getIdentityLabels(uint32(endpoint.Identity.ID))
			if err != nil {
				logger.WithFields(logrus.Fields{logfields.K8sEndpointName: endpoint.Name, logfields.K8sNamespace: endpoint.Namespace}).
					WithError(err).Error("Could not get endpoint identity labels, skipping from VRF matching")
				continue
			}
			if !rule.selectsEndpoint(labels.K8sStringMap()) {
				continue
			}
			var ips []net.IP
			for _, pair := range endpoint.Networking.Addressing {
				if pair.IPV4 != "" {
					ips = append(ips, net.ParseIP(pair.IPV4).To4())
				}
				if pair.IPV6 != "" {
					ips = append(ips, net.ParseIP(pair.IPV6).To16())
				}
			}
			for i := range ips {
				for _, dstCIDR := range rule.dstCIDRs {
					keys = append(keys, srv6map.VRFKey{
						SourceIP: &(ips[i]),
						DestCIDR: dstCIDR,
					})
				}
			}
		}
	}
	return keys
}

// VRFRule is the internal representation of rules from CiliumSRv6VRF.
type VRFRule struct {
	endpointSelectors []api.EndpointSelector
	dstCIDRs          []*net.IPNet
}

// deepcopy-gen cannot generate a DeepCopyInto for net.IPNet. Define by ourselves.
func (in *VRFRule) DeepCopy() *VRFRule {
	if in == nil {
		return nil
	}
	out := new(VRFRule)
	in.DeepCopyInto(out)
	return out
}

func (in *VRFRule) DeepCopyInto(out *VRFRule) {
	if in.endpointSelectors != nil {
		out.endpointSelectors = make([]api.EndpointSelector, len(in.endpointSelectors))
		for i, selector := range in.endpointSelectors {
			selector.DeepCopyInto(&out.endpointSelectors[i])
		}
	}
	if in.dstCIDRs != nil {
		out.dstCIDRs = make([]*net.IPNet, len(in.dstCIDRs))
		for i, cidr := range in.dstCIDRs {
			out.dstCIDRs[i] = &net.IPNet{
				IP:   make(net.IP, len(cidr.IP)),
				Mask: make(net.IPMask, len(cidr.Mask)),
			}
			copy(out.dstCIDRs[i].IP, cidr.IP)
			copy(out.dstCIDRs[i].Mask, cidr.Mask)
		}
	}
}

// vrfID includes policy name and namespace
type vrfID = types.NamespacedName

// selectsEndpoint determines if the given endpoint is selected by the VRFRule
// based on matching labels of policy and endpoint.
func (rule *VRFRule) selectsEndpoint(endpointLabels map[string]string) bool {
	labelsToMatch := k8sLabels.Set(endpointLabels)
	for _, selector := range rule.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

func ParseVRF(csrvrf *v2alpha1.CiliumSRv6VRF) (*VRF, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet
	var rules []VRFRule

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
	name := csrvrf.ObjectMeta.Name

	if name == "" {
		return nil, fmt.Errorf("CiliumEgressSRv6Policy must have a name")
	}

	for _, rule := range csrvrf.Spec.Rules {
		for _, cidrString := range rule.DestinationCIDRs {
			_, cidr, err := net.ParseCIDR(string(cidrString))
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{logfields.CiliumSRv6VRFName: name}).Warn("Error parsing CIDR.")
				return nil, err
			}
			dstCidrList = append(dstCidrList, cidr)
		}

		for _, selector := range rule.Selectors {
			if selector.NamespaceSelector != nil {
				prefixedNsSelector := selector.NamespaceSelector
				matchLabels := map[string]string{}
				// We use our own special label prefix for namespace metadata,
				// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
				for k, v := range selector.NamespaceSelector.MatchLabels {
					matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
				}

				prefixedNsSelector.MatchLabels = matchLabels

				// We use our own special label prefix for namespace metadata,
				// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
				for i, lsr := range selector.NamespaceSelector.MatchExpressions {
					lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
					prefixedNsSelector.MatchExpressions[i] = lsr
				}

				// Empty namespace selector selects all namespaces (i.e., a namespace
				// label exists).
				if len(selector.NamespaceSelector.MatchLabels) == 0 && len(selector.NamespaceSelector.MatchExpressions) == 0 {
					prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
				}

				endpointSelectorList = append(
					endpointSelectorList,
					api.NewESFromK8sLabelSelector("", prefixedNsSelector, selector.PodSelector))
			} else if selector.PodSelector != nil {
				endpointSelectorList = append(
					endpointSelectorList,
					api.NewESFromK8sLabelSelector("", selector.PodSelector))
			} else {
				return nil, fmt.Errorf("CiliumSRv6VRF cannot have both nil namespace selector and nil pod selector")
			}
		}

		rules = append(rules, VRFRule{
			endpointSelectors: endpointSelectorList,
			dstCIDRs:          dstCidrList,
		})
	}

	return &VRF{
		id: types.NamespacedName{
			Name: name,
		},
		VRFID:             csrvrf.Spec.VRFID,
		ImportRouteTarget: csrvrf.Spec.ImportRouteTarget,
		ExportRouteTarget: csrvrf.Spec.ExportRouteTarget,
		rules:             rules,
		LocatorPool:       csrvrf.Spec.LocatorPoolRef,
	}, nil
}

// ParsePolicyConfigID takes a CiliumSRv6VRF CR and returns only the
// config id.
func ParseVRFID(csrvrf *v2alpha1.CiliumSRv6VRF) types.NamespacedName {
	return vrfID{
		Name: csrvrf.Name,
	}
}
