//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="isovalentegressgatewaypolicy",path="isovalentegressgatewaypolicies",scope="Cluster",shortName={iegp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type IsovalentEgressGatewayPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentEgressGatewayPolicySpec `json:"spec,omitempty"`

	// Status is the status of the Isovalent egress gateway policy.
	//
	// +kubebuilder:validation:Optional
	Status IsovalentEgressGatewayPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentEgressGatewayPolicyList is a list of IsovalentEgressGatewayPolicy objects.
type IsovalentEgressGatewayPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentEgressGatewayPolicy.
	Items []IsovalentEgressGatewayPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
type IPv4CIDR string

type IsovalentEgressGatewayPolicySpec struct {
	// Egress represents a list of rules by which egress traffic is
	// filtered from the source pods.
	Selectors []EgressRule `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []IPv4CIDR `json:"destinationCIDRs"`

	// ExcludedCIDRs is a list of destination CIDRs that will be excluded
	// from the egress gateway redirection and SNAT logic.
	// Should be a subset of destinationCIDRs otherwise it will not have any
	// effect.
	//
	// +kubebuilder:validation:Optional
	ExcludedCIDRs []IPv4CIDR `json:"excludedCIDRs"`

	// EgressGroup represents a group of nodes which will act as egress
	// gateway for the given policy.
	EgressGroups []EgressGroup `json:"egressGroups"`

	// BGPEnabled controls whether the policy's egress IPs should be
	// announced via BGP.
	//
	// +kubebuilder:validation:Optional
	BGPEnabled bool `json:"bgpEnabled"`
}

type EgressRule struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}

// EgressGroup identifies a group of nodes that should act as egress gateways
// for a given policy. In addition to that it also specifies the configuration
// of said nodes (which egress IP or network interface should be used to SNAT
// traffic).
type EgressGroup struct {
	// This is a label selector which selects nodes. This field follows standard label
	// selector semantics; if present but empty, it selects all nodes.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// Interface is the network interface to which the egress IP is assigned.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	Interface string `json:"interface,omitempty"`

	// EgressIP is a source IP address that the egress traffic is redirected
	// to and SNATed with.
	//
	// Example:
	// When it is set to "192.168.1.100", matched egress packets will be
	// redirected to node with IP 192.168.1.100 and SNAT’ed with IP address 192.168.1.100.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	//
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	EgressIP string `json:"egressIP,omitempty"`

	// MaxGatewayNodes indicates the maximum number of nodes in the node
	// group that can operate as egress gateway simultaneously
	//
	// +kubebuilder:validation:Optional
	MaxGatewayNodes int `json:"maxGatewayNodes"`
}

// +deepequal-gen=true

// IsovalentEgressGatewayPolicyStatus is a slice a IsovalentEgressGatewayPolicyGroupStatus,
// where each element represents the status of a given EgressGroup.
type IsovalentEgressGatewayPolicyStatus struct {
	ObservedGeneration int64                                     `json:"observedGeneration,omitempty"`
	GroupStatuses      []IsovalentEgressGatewayPolicyGroupStatus `json:"groupStatuses"`
}

// IsovalentEgressGatewayPolicyGroupStatus is the status of a Isovalent egress gateway
// policy group. It consists of a pair of slices that describe the set of active
// and healthy gateway IPs for a given EgressGroup.
type IsovalentEgressGatewayPolicyGroupStatus struct {
	ActiveGatewayIPs  []string `json:"activeGatewayIPs,omitempty"`
	HealthyGatewayIPs []string `json:"healthyGatewayIPs,omitempty"`
}
