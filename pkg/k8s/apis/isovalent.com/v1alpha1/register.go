// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.CustomResourceDefinitionGroup

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v1alpha1"

	// IsovalentFQDNGroup (IFG)
	IFGPluralName     = "isovalentfqdngroups"
	IFGKindDefinition = "IsovalentFQDNGroup"
	IFGName           = IFGPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentSRv6SIDManager (SRv6SIDManager)
	SRv6SIDManagerPluralName     = "isovalentsrv6sidmanagers"
	SRv6SIDManagerKindDefinition = "IsovalentSRv6SIDManager"
	SRv6SIDManagerName           = SRv6SIDManagerPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentPodNetwork (IPN)
	IPNPluralName     = "isovalentpodnetworks"
	IPNKindDefinition = "IsovalentPodNetwork"
	IPNName           = IPNPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentSRv6LocatorPool (SRv6LocatorPool)
	SRv6LocatorPoolPluralName     = "isovalentsrv6locatorpools"
	SRv6LocatorPoolKindDefinition = "IsovalentSRv6LocatorPool"
	SRv6LocatorPoolName           = SRv6LocatorPoolPluralName + "." + CustomResourceDefinitionGroup
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&IsovalentFQDNGroup{},
		&IsovalentFQDNGroupList{},
		&IsovalentSRv6SIDManager{},
		&IsovalentSRv6LocatorPool{},
		&IsovalentSRv6LocatorPoolList{},
		&IsovalentSRv6SIDManagerList{},
		&IsovalentPodNetwork{},
		&IsovalentPodNetworkList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
