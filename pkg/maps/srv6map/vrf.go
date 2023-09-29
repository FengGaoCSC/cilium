// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/types"
)

const (
	VRFMapName4   = "cilium_srv6_vrf_v4"
	VRFMapName6   = "cilium_srv6_vrf_v6"
	MaxVRFEntries = 16384
)

var (
	SRv6VRFMap4 *srv6VRFMap
	SRv6VRFMap6 *srv6VRFMap
)

// Generic VRF mapping key for IPv4 and IPv6.
type VRFKey struct {
	SourceIP *net.IP
	DestCIDR *net.IPNet
}

func (a *VRFKey) Equal(b *VRFKey) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.SourceIP.Equal(*b.SourceIP) &&
		a.DestCIDR.IP.Equal(b.DestCIDR.IP) &&
		slices.Equal(a.DestCIDR.Mask, b.DestCIDR.Mask)
}

func (k *VRFKey) String() string {
	return fmt.Sprintf("%s %s", k.SourceIP, k.DestCIDR)
}

// Match returns true if the sourceIP and destCIDR parameters match the SRv6
// policy key.
func (k *VRFKey) Match(srcIP net.IP, cidr *net.IPNet) bool {
	return k.SourceIP.String() == srcIP.String() && k.DestCIDR.String() == cidr.String()
}

// IsIPv6 returns true if the key is for an IPv6 endpoint.
func (k *VRFKey) IsIPv6() bool {
	return ip.IsIPv6(*k.SourceIP)
}

// VRFValue implements the bpf.MapValue interface. It contains the
// VRF ID for SRv6 lookups.
type VRFValue struct {
	ID uint32
}

func (a *VRFValue) Equal(b *VRFValue) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.ID == b.ID
}

// String pretty prints the VRF ID.
func (v *VRFValue) String() string {
	return fmt.Sprintf("%d", v.ID)
}

func initVRFMaps(create bool) error {
	var m4, m6 *ebpf.Map
	var err error

	if create {
		m4 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       VRFMapName4,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(VRFKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(VRFValue{})),
			MaxEntries: uint32(MaxVRFEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m4.OpenOrCreate(); err != nil {
			return err
		}

		m6 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       VRFMapName6,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(VRFKey6{})),
			ValueSize:  uint32(unsafe.Sizeof(VRFValue{})),
			MaxEntries: uint32(MaxVRFEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m6.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		if m4, err = ebpf.LoadRegisterMap(VRFMapName4); err != nil {
			return err
		}
		if m6, err = ebpf.LoadRegisterMap(VRFMapName6); err != nil {
			return err
		}
	}

	SRv6VRFMap4 = &srv6VRFMap{
		m4,
	}
	SRv6VRFMap6 = &srv6VRFMap{
		m6,
	}

	return nil
}

func CreateVRFMaps() error {
	return initVRFMaps(true)
}

func OpenVRFMaps() error {
	return initVRFMaps(false)
}

func VRFMapsInitialized() bool {
	return SRv6VRFMap4 != nil && SRv6VRFMap6 != nil
}

// srv6VRFMap is the internal representation of an SRv6 VRF mapping map.
type srv6VRFMap struct {
	*ebpf.Map
}

type VRFKey4 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32

	SourceIP types.IPv4
	DestCIDR types.IPv4
}

type VRFKey6 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32

	SourceIP types.IPv6
	DestCIDR types.IPv6
}

// toIPv4 converts the generic VRFKey into an IPv4 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv4() VRFKey4 {
	result := VRFKey4{}
	ones, _ := k.DestCIDR.Mask.Size()

	copy(result.SourceIP[:], k.SourceIP.To4())
	copy(result.DestCIDR[:], k.DestCIDR.IP.To4())
	result.PrefixLen = uint32(unsafe.Sizeof(result.SourceIP)*8) + uint32(ones)

	return result
}

// toIPv6 converts the generic VRFKey into an IPv6 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv6() VRFKey6 {
	result := VRFKey6{}
	ones, _ := k.DestCIDR.Mask.Size()

	copy(result.SourceIP[:], k.SourceIP.To16())
	copy(result.DestCIDR[:], k.DestCIDR.IP.To16())
	result.PrefixLen = uint32(unsafe.Sizeof(result.SourceIP)*8) + uint32(ones)

	return result
}

func (k *VRFKey4) getDestCIDR() *net.IPNet {
	staticPrefixBits := uint32(unsafe.Sizeof(k.SourceIP) * 8)
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-staticPrefixBits), 32),
	}
}

func (k *VRFKey6) getDestCIDR() *net.IPNet {
	staticPrefixBits := uint32(unsafe.Sizeof(k.SourceIP) * 8)
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-staticPrefixBits), 128),
	}
}

func (m *srv6VRFMap) Lookup(key VRFKey, val *VRFValue) error {
	if key.IsIPv6() {
		return m.Map.Lookup(key.toIPv6(), val)
	}
	return m.Map.Lookup(key.toIPv4(), val)
}

func (m *srv6VRFMap) Update(key VRFKey, vrfID uint32) error {
	val := VRFValue{ID: vrfID}
	if key.IsIPv6() {
		return m.Map.Update(key.toIPv6(), val, 0)
	}
	return m.Map.Update(key.toIPv4(), val, 0)
}

func (m *srv6VRFMap) Delete(key VRFKey) error {
	if key.IsIPv6() {
		return m.Map.Delete(key.toIPv6())
	}
	return m.Map.Delete(key.toIPv4())
}

// GetVRFMap returns the appropriate VRF mapping map (IPv4 or IPv6)
// for the given key.
func GetVRFMap(key VRFKey) *srv6VRFMap {
	if key.IsIPv6() {
		return SRv6VRFMap6
	}
	return SRv6VRFMap4
}

// SRv6VRFIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 policy map.
type SRv6VRFIterateCallback func(*VRFKey, *VRFValue)

// IterateWithCallback4 iterates through the IPv4 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m srv6VRFMap) IterateWithCallback4(cb SRv6VRFIterateCallback) error {
	return m.Map.IterateWithCallback(&VRFKey4{}, &VRFValue{},
		func(k, v interface{}) {
			key4 := k.(*VRFKey4)
			srcIP := key4.SourceIP.IP()
			key := VRFKey{
				SourceIP: &srcIP,
				DestCIDR: key4.getDestCIDR(),
			}
			value := v.(*VRFValue)

			cb(&key, value)
		})
}

// IterateWithCallback6 iterates through the IPv6 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m srv6VRFMap) IterateWithCallback6(cb SRv6VRFIterateCallback) error {
	return m.Map.IterateWithCallback(&VRFKey6{}, &VRFValue{},
		func(k, v interface{}) {
			key6 := k.(*VRFKey6)
			srcIP := key6.SourceIP.IP()
			key := VRFKey{
				SourceIP: &srcIP,
				DestCIDR: key6.getDestCIDR(),
			}
			value := v.(*VRFValue)

			cb(&key, value)
		})
}
