// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentsrv6sidmanager",path="isovalentsrv6sidmanagers",scope="Cluster",shortName={sidmanager}
// +kubebuilder:storageversion
type IsovalentSRv6SIDManager struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec of the SID Manager.
	//
	// +kubebuilder:validation:Required
	Spec IsovalentSRv6SIDManagerSpec `json:"spec"`

	// Status is a status of the SID Manager.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status *IsovalentSRv6SIDManagerStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentSRv6SIDManagerList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentSRv6SIDManager `json:"items"`
}

type IsovalentSRv6SIDManagerSpec struct {
	// LocatorAllocations is a list of locators allocated for this SID manager.
	//
	// +kubebuilder:validation:Required
	// +listType=map
	// +listMapKey=poolRef
	LocatorAllocations []*IsovalentSRv6LocatorAllocation `json:"locatorAllocations"`
}

type IsovalentSRv6SIDManagerStatus struct {
	// SIDAllocations is a list of SIDs allocated by this SID manager.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=poolRef
	SIDAllocations []*IsovalentSRv6SIDAllocation `json:"sidAllocations"`
}

type IsovalentSRv6LocatorAllocation struct {
	// PoolRef is a reference to the pool that this locator is allocated from
	//
	// +kubebuilder:validation:Required
	PoolRef string `json:"poolRef"`

	// Locators is a list of locators allocated from the pool
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxItems=1
	Locators []*IsovalentSRv6Locator `json:"locators"`
}

type IsovalentSRv6Locator struct {
	// Prefix is a locator prefix.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))/([0-9]|[0-9][0-9]|1[0-1][0-9]|12[0-8])$"
	Prefix string `json:"prefix"`

	// Structure is a structure of the SID. This will be derived from
	// the Structure in the IsovalentSRv6LocatorPool definition.
	//
	// +kubebuilder:validation:Required
	Structure IsovalentSRv6SIDStructure `json:"structure"`
}

type IsovalentSRv6SIDAllocation struct {
	// PoolRef is a reference to the pool that this SID is allocated from
	//
	// +kubebuilder:validation:Required
	PoolRef string `json:"poolRef"`

	// SIDs is a list of SID allocation information
	//
	// +kubebuilder:validation:Required
	SIDs []*IsovalentSRv6SIDInfo `json:"sids"`
}

type IsovalentSRv6SIDInfo struct {
	// SID is a pair of IPv6 address and structure information
	//
	// +kubebuilder:validation:Required
	SID IsovalentSRv6SID `json:"sid"`

	// Owner is an owner of the SID
	//
	// +kubebuilder:validation:Required
	Owner string `json:"owner"`

	// MetaData is a metadata associated with the SID
	//
	// +kubebuilder:validation:Required
	MetaData string `json:"metadata"`

	// Behavior is an SRv6 behavior as defined in RFC8986 associated with the SID
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=End.DT4;End.DT6;End.DT46
	Behavior string `json:"behavior"`
}

type IsovalentSRv6SID struct {
	// Addr is an IPv6 address represents the SID
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv6
	Addr string `json:"addr"`

	// Structure is a structure of this SID
	//
	// +kubebuilder:validation:Required
	Structure IsovalentSRv6SIDStructure `json:"structure"`
}

type IsovalentSRv6SIDStructure struct {
	// Locator Block length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LocatorBlockLenBits uint8 `json:"locatorBlockLenBits"`

	// Locator Node length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LocatorNodeLenBits uint8 `json:"locatorNodeLenBits"`

	// Function length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	FunctionLenBits uint8 `json:"functionLenBits"`

	// Argument length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	ArgumentLenBits uint8 `json:"argumentLenBits"`
}
