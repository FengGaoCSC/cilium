// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentfqdngroup",path="isovalentfqdngroups",scope="Cluster",shortName={ifg}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// IsovalentFQDNGroup is a list of FQDNs to be periodically resolved.
type IsovalentFQDNGroup struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec IsovalentFQDNGroupSpec `json:"spec"`
}

type IsovalentFQDNGroupSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	FQDNs []FQDN `json:"fqdns"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

type IsovalentFQDNGroupList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IsovalentFQDNGroup `json:"items"`
}

// FQDN is a Fully Qualified Domain Name.
//
// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_]+[.]?)+$`
type FQDN string
