// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	netutils "k8s.io/utils/net"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName4   = "cilium_srv6_policy_v4"
	PolicyMapName6   = "cilium_srv6_policy_v6"
	MaxPolicyEntries = 16384

	// policyStaticPrefixBits represents the size in bits of the static
	// prefix part of an policy key (i.e. the VRF ID).
	policyStaticPrefixBits = uint32(unsafe.Sizeof(uint32(0)) * 8)
)

var (
	SRv6PolicyMap4 *srv6PolicyMap
	SRv6PolicyMap6 *srv6PolicyMap
)

// Generic policy key for IPv4 and IPv6.
type PolicyKey struct {
	VRFID    uint32
	DestCIDR *net.IPNet
}

func (a *PolicyKey) Equal(b *PolicyKey) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.VRFID == b.VRFID &&
		a.DestCIDR.IP.Equal(b.DestCIDR.IP) &&
		slices.Equal(a.DestCIDR.Mask, b.DestCIDR.Mask)
}

func (k *PolicyKey) String() string {
	return fmt.Sprintf("%d %s", k.VRFID, k.DestCIDR)
}

// Match returns true if the vrfID and destCIDR parameters match the SRv6
// policy key.
func (k *PolicyKey) Match(vrfID uint32, cidr *net.IPNet) bool {
	return k.VRFID == vrfID && k.DestCIDR.String() == cidr.String()
}

// IsIPv6 returns true if the key is for an IPv6 destination CIDR.
func (k *PolicyKey) IsIPv6() bool {
	return netutils.IsIPv6CIDR(k.DestCIDR)
}

type PolicyValue struct {
	SID types.IPv6
}

func (a *PolicyValue) Equal(b *PolicyValue) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.SID.IP().Equal(b.SID.IP())
}

// String pretty print the SID.
func (v *PolicyValue) String() string {
	return fmt.Sprintf("%s", v.SID)
}

func initPolicyMaps(create bool) error {
	var m4, m6 *ebpf.Map
	var err error

	if create {
		m4 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       PolicyMapName4,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(PolicyKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(PolicyValue{})),
			MaxEntries: uint32(MaxPolicyEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m4.OpenOrCreate(); err != nil {
			return err
		}

		m6 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       PolicyMapName6,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(PolicyKey6{})),
			ValueSize:  uint32(unsafe.Sizeof(PolicyValue{})),
			MaxEntries: uint32(MaxPolicyEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m6.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		if m4, err = ebpf.LoadRegisterMap(PolicyMapName4); err != nil {
			return err
		}
		if m6, err = ebpf.LoadRegisterMap(PolicyMapName6); err != nil {
			return err
		}
	}

	SRv6PolicyMap4 = &srv6PolicyMap{
		m4,
	}
	SRv6PolicyMap6 = &srv6PolicyMap{
		m6,
	}

	return nil
}

func CreatePolicyMaps() error {
	return initPolicyMaps(true)
}

func OpenPolicyMaps() error {
	return initPolicyMaps(false)
}

// srv6PolicyMap is the internal representation of an SRv6 policy map.
type srv6PolicyMap struct {
	*ebpf.Map
}

type PolicyKey4 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32

	VRFID    uint32
	DestCIDR types.IPv4
}

type PolicyKey6 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32

	VRFID    uint32
	DestCIDR types.IPv6
}

// toIPv4 converts the generic PolicyKey into an IPv4 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv4() PolicyKey4 {
	result := PolicyKey4{}
	ones, _ := k.DestCIDR.Mask.Size()

	result.VRFID = k.VRFID
	copy(result.DestCIDR[:], k.DestCIDR.IP.To4())
	result.PrefixLen = policyStaticPrefixBits + uint32(ones)

	return result
}

// toIPv6 converts the generic PolicyKey into an IPv6 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv6() PolicyKey6 {
	result := PolicyKey6{}
	ones, _ := k.DestCIDR.Mask.Size()

	result.VRFID = k.VRFID
	copy(result.DestCIDR[:], k.DestCIDR.IP.To16())
	result.PrefixLen = policyStaticPrefixBits + uint32(ones)

	return result
}

func (k *PolicyKey4) getDestCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-policyStaticPrefixBits), 32),
	}
}

func (k *PolicyKey6) getDestCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-policyStaticPrefixBits), 128),
	}
}

func (m *srv6PolicyMap) Lookup(key PolicyKey, val *PolicyValue) error {
	if key.IsIPv6() {
		return m.Map.Lookup(key.toIPv6(), val)
	}
	return m.Map.Lookup(key.toIPv4(), val)
}

func (m *srv6PolicyMap) Update(key PolicyKey, sid types.IPv6) error {
	val := PolicyValue{SID: sid}
	if key.IsIPv6() {
		return m.Map.Update(key.toIPv6(), val, 0)
	}
	return m.Map.Update(key.toIPv4(), val, 0)
}

func (m *srv6PolicyMap) Delete(key PolicyKey) error {
	if key.IsIPv6() {
		return m.Map.Delete(key.toIPv6())
	}
	return m.Map.Delete(key.toIPv4())
}

// SRv6PolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 policy map.
type SRv6PolicyIterateCallback func(*PolicyKey, *PolicyValue)

// IterateWithCallback4 iterates through the IPv4 keys/values of an egress
// policy map, passing each key/value pair to the cb callback.
func (m srv6PolicyMap) IterateWithCallback4(cb SRv6PolicyIterateCallback) error {
	return m.Map.IterateWithCallback(&PolicyKey4{}, &PolicyValue{},
		func(k, v interface{}) {
			key4 := k.(*PolicyKey4)
			key := PolicyKey{
				VRFID:    key4.VRFID,
				DestCIDR: key4.getDestCIDR(),
			}
			value := v.(*PolicyValue)

			cb(&key, value)
		})
}

// IterateWithCallback6 iterates through the IPv6 keys/values of an egress
// policy map, passing each key/value pair to the cb callback.
func (m srv6PolicyMap) IterateWithCallback6(cb SRv6PolicyIterateCallback) error {
	return m.Map.IterateWithCallback(&PolicyKey6{}, &PolicyValue{},
		func(k, v interface{}) {
			key6 := k.(*PolicyKey6)
			key := PolicyKey{
				VRFID:    key6.VRFID,
				DestCIDR: key6.getDestCIDR(),
			}
			value := v.(*PolicyValue)

			cb(&key, value)
		})
}

// GetPolicyMap returns the appropriate egress policy map (IPv4 or IPv6)
// for the given key.
func GetPolicyMap(key PolicyKey) *srv6PolicyMap {
	if key.IsIPv6() {
		return SRv6PolicyMap6
	}
	return SRv6PolicyMap4
}
