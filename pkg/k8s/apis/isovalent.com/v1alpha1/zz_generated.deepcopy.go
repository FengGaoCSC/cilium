//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPAMPoolSpec) DeepCopyInto(out *IPAMPoolSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPAMPoolSpec.
func (in *IPAMPoolSpec) DeepCopy() *IPAMPoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPAMPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPAMSpec) DeepCopyInto(out *IPAMSpec) {
	*out = *in
	out.Pool = in.Pool
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPAMSpec.
func (in *IPAMSpec) DeepCopy() *IPAMSpec {
	if in == nil {
		return nil
	}
	out := new(IPAMSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroup) DeepCopyInto(out *IsovalentFQDNGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroup.
func (in *IsovalentFQDNGroup) DeepCopy() *IsovalentFQDNGroup {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentFQDNGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroupList) DeepCopyInto(out *IsovalentFQDNGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentFQDNGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroupList.
func (in *IsovalentFQDNGroupList) DeepCopy() *IsovalentFQDNGroupList {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentFQDNGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroupSpec) DeepCopyInto(out *IsovalentFQDNGroupSpec) {
	*out = *in
	if in.FQDNs != nil {
		in, out := &in.FQDNs, &out.FQDNs
		*out = make([]FQDN, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroupSpec.
func (in *IsovalentFQDNGroupSpec) DeepCopy() *IsovalentFQDNGroupSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentPodNetwork) DeepCopyInto(out *IsovalentPodNetwork) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentPodNetwork.
func (in *IsovalentPodNetwork) DeepCopy() *IsovalentPodNetwork {
	if in == nil {
		return nil
	}
	out := new(IsovalentPodNetwork)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentPodNetwork) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentPodNetworkList) DeepCopyInto(out *IsovalentPodNetworkList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentPodNetwork, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentPodNetworkList.
func (in *IsovalentPodNetworkList) DeepCopy() *IsovalentPodNetworkList {
	if in == nil {
		return nil
	}
	out := new(IsovalentPodNetworkList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentPodNetworkList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6Locator) DeepCopyInto(out *IsovalentSRv6Locator) {
	*out = *in
	out.Structure = in.Structure
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6Locator.
func (in *IsovalentSRv6Locator) DeepCopy() *IsovalentSRv6Locator {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6Locator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6LocatorAllocation) DeepCopyInto(out *IsovalentSRv6LocatorAllocation) {
	*out = *in
	if in.Locators != nil {
		in, out := &in.Locators, &out.Locators
		*out = make([]*IsovalentSRv6Locator, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6Locator)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6LocatorAllocation.
func (in *IsovalentSRv6LocatorAllocation) DeepCopy() *IsovalentSRv6LocatorAllocation {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6LocatorAllocation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SID) DeepCopyInto(out *IsovalentSRv6SID) {
	*out = *in
	out.Structure = in.Structure
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SID.
func (in *IsovalentSRv6SID) DeepCopy() *IsovalentSRv6SID {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SID)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDAllocation) DeepCopyInto(out *IsovalentSRv6SIDAllocation) {
	*out = *in
	if in.SIDs != nil {
		in, out := &in.SIDs, &out.SIDs
		*out = make([]*IsovalentSRv6SIDInfo, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6SIDInfo)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDAllocation.
func (in *IsovalentSRv6SIDAllocation) DeepCopy() *IsovalentSRv6SIDAllocation {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDAllocation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDInfo) DeepCopyInto(out *IsovalentSRv6SIDInfo) {
	*out = *in
	out.SID = in.SID
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDInfo.
func (in *IsovalentSRv6SIDInfo) DeepCopy() *IsovalentSRv6SIDInfo {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManager) DeepCopyInto(out *IsovalentSRv6SIDManager) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(IsovalentSRv6SIDManagerStatus)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManager.
func (in *IsovalentSRv6SIDManager) DeepCopy() *IsovalentSRv6SIDManager {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManager)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6SIDManager) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerList) DeepCopyInto(out *IsovalentSRv6SIDManagerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentSRv6SIDManager, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerList.
func (in *IsovalentSRv6SIDManagerList) DeepCopy() *IsovalentSRv6SIDManagerList {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6SIDManagerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerSpec) DeepCopyInto(out *IsovalentSRv6SIDManagerSpec) {
	*out = *in
	if in.LocatorAllocations != nil {
		in, out := &in.LocatorAllocations, &out.LocatorAllocations
		*out = make([]*IsovalentSRv6LocatorAllocation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6LocatorAllocation)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerSpec.
func (in *IsovalentSRv6SIDManagerSpec) DeepCopy() *IsovalentSRv6SIDManagerSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerStatus) DeepCopyInto(out *IsovalentSRv6SIDManagerStatus) {
	*out = *in
	if in.SIDAllocations != nil {
		in, out := &in.SIDAllocations, &out.SIDAllocations
		*out = make([]*IsovalentSRv6SIDAllocation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6SIDAllocation)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerStatus.
func (in *IsovalentSRv6SIDManagerStatus) DeepCopy() *IsovalentSRv6SIDManagerStatus {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDStructure) DeepCopyInto(out *IsovalentSRv6SIDStructure) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDStructure.
func (in *IsovalentSRv6SIDStructure) DeepCopy() *IsovalentSRv6SIDStructure {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDStructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PodNetworkSpec) DeepCopyInto(out *PodNetworkSpec) {
	*out = *in
	out.IPAM = in.IPAM
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]RouteSpec, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodNetworkSpec.
func (in *PodNetworkSpec) DeepCopy() *PodNetworkSpec {
	if in == nil {
		return nil
	}
	out := new(PodNetworkSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RouteSpec) DeepCopyInto(out *RouteSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RouteSpec.
func (in *RouteSpec) DeepCopy() *RouteSpec {
	if in == nil {
		return nil
	}
	out := new(RouteSpec)
	in.DeepCopyInto(out)
	return out
}