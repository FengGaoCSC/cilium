// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

func CreateMaps() {
	CreatePolicyMaps()
	CreateSIDMap()
	CreateVRFMaps()
}

func DeleteMaps() {
	SRv6PolicyMap4.Close()
	SRv6PolicyMap4.Unpin()
	SRv6PolicyMap6.Close()
	SRv6PolicyMap6.Unpin()
	SRv6SIDMap.Close()
	SRv6SIDMap.Unpin()
	SRv6VRFMap4.Close()
	SRv6VRFMap4.Unpin()
	SRv6VRFMap6.Close()
	SRv6VRFMap6.Unpin()
}
