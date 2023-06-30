// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentpodnetwork",path="isovalentpodnetworks",scope="Cluster",shortName={ipn}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// IsovalentPodNetwork defines a network to which pods can be attached.
type IsovalentPodNetwork struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec PodNetworkSpec `json:"spec"`
}

// PodNetworkSpec is the pod network specification.
type PodNetworkSpec struct {
	// IPAM is the IPAM specificatiojn for this network.
	//
	// +kubebuilder:validation:Required
	IPAM IPAMSpec `json:"ipam"`

	// Routes are the routing specifications for this network.
	//
	// +kubebuilder:validation:Optional
	Routes []RouteSpec `json:"routes"`
}

// IPAMSpec is the IPAM specification for a pod network.
type IPAMSpec struct {
	// Mode is the IPAM mode used for this network. Currently only multi-pool is supported.
	//
	// +kubebuilder:validation:Required
	Mode IPAMMode `json:"mode"`

	// Pool is the IPAM pool to use for this network.
	//
	// +kubebuilder:validation:Required
	Pool IPAMPoolSpec `json:"pool"`
}

// IPAMMode is the IPAM mode for a pod network.
//
// +kubebuilder:validation:Enum=multi-pool
type IPAMMode string

// IPAMPoolSpec is the IPAM pool specification for a pod network.
type IPAMPoolSpec struct {
	// Name is the IPAM pool's name.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// RouteSpec is the routing specification for a pod network.
type RouteSpec struct {
	// Destination is the route's destination CIDR.
	//
	// +kubebuilder:validation:Required
	Destination CIDR `json:"destination"`

	// Gateway is the route's gateway IP address.
	//
	// +kubebuilder:validation:Optional
	Gateway IP `json:"gateway"`
}

// CIDR is network CIDR.
//
// +kubebuilder:validation:Format=cidr
type CIDR string

// IP is an IP address (IPv4 or IPv6)
//
// +kubebuilder:validation:Format=ip
type IP string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// IsovalentPodNetworkList is a list of IsovalentPodNetwork objects.
type IsovalentPodNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of IsovalentPodNetworks.
	Items []IsovalentPodNetwork `json:"items"`
}
