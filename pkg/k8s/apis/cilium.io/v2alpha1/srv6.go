// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumsrv6egresspolicy",path="ciliumsrv6egresspolicies",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumSRv6EgressPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumSRv6EgressPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumSRv6EgressPolicyList is a list of CiliumSRv6EgressPolicy objects.
type CiliumSRv6EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumSRv6EgressPolicy.
	Items []CiliumSRv6EgressPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
type CIDR string

type CiliumSRv6EgressPolicySpec struct {
	// VRFID is the ID of the VRF in which the SIDs should be looked up.
	VRFID uint32 `json:"vrfID"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`

	// DestinationSID is the SID used for the SRv6 encapsulation.
	// It is in effect the IPv6 destination address of the outer IPv6 header.
	//
	// +kubebuilder:validation:Pattern=`^\s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?$`
	DestinationSID string `json:"destinationSID"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumsrv6vrf",path="ciliumsrv6vrfs",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumSRv6VRF struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumSRv6VRFSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumSRv6VRFList is a list of CiliumSRv6VRF objects.
type CiliumSRv6VRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumSRv6VRF.
	Items []CiliumSRv6VRF `json:"items"`
}

type VRFRule struct {
	// Selectors represents a list of rules to select pods that can use a
	// given VRF.
	Selectors []EgressRule `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`
}

type CiliumSRv6VRFSpec struct {
	// VRFID is the ID of the VRF in which the SIDs should be looked up.
	VRFID uint32 `json:"vrfID"`

	// ImportRouteTarget is the import route-target for this VRF. It is optional and,
	// if specified, will be used by the BGP manager to know in which VRF to install
	// received routes.
	ImportRouteTarget string `json:"importRouteTarget,omitempty"`

	// ExportRouteTarget is the export route-target for this VRF. It is optional and,
	// if specified, will instruct the SRv6 Manager to allocate a SID for this VRF
	// and signal the BGP manager to create VPNv4 advertisements over applicable
	// speakers.
	ExportRouteTarget string `json:"exportRouteTarget,omitempty"`

	// LocatorPoolRef specifies a name of the locator pool that the SRv6
	// SID for this VRF will be allocated from.
	LocatorPoolRef string `json:"locatorPoolRef,omitempty"`

	// Rules describes what traffic is assigned to the VRF. Egress packets are matched
	// against these rules to know to in which VRF the SID should be looked up.
	Rules []VRFRule `json:"rules"`
}
