//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"fmt"
	"net/netip"
)

// Locator represents a single Locator. It embeds the netip.Prefix, so it can
// be treated as an IP address. In addition to that, it holds a SID structure
// information.
type Locator struct {
	netip.Prefix
	structure SIDStructure
}

// NewLocator constructs Locator from IPv6 netip.Prefix and SIDStructure
func NewLocator(prefix netip.Prefix, structure *SIDStructure) (*Locator, error) {
	if !prefix.Addr().Is6() {
		return nil, fmt.Errorf("locator prefix must be IPv6")
	}

	if prefix.Bits() != int(structure.LocatorLenBits()) {
		return nil, fmt.Errorf("locator prefix length (%d) doesn't match with structure (%d)",
			prefix.Bits(), structure.LocatorLenBits())
	}

	return &Locator{
		Prefix:    prefix,
		structure: *structure,
	}, nil
}

// MustNewLocator is NewLocator but panics on error. Should be used only in tests.
func MustNewLocator(prefix netip.Prefix, structure *SIDStructure) *Locator {
	l, err := NewLocator(prefix, structure)
	if err != nil {
		panic(err)
	}
	return l
}

// Structure returns a pointer to the SID structure
func (l *Locator) Structure() *SIDStructure {
	return &l.structure
}

// String returns a human-readable string representation of this Locator
func (l *Locator) String() string {
	return l.Prefix.String() + l.structure.String()
}

// SID represents a single SID. It embeds the netip.Addr, so it can be treated
// as an IP address. In addition to that, it holds a SID structure information
// and implements some helper functions to manipulate part of that.
type SID struct {
	netip.Addr
	structure SIDStructure
}

// NewSID constructs SID from IPv6 netip.Addr and SIDStructure
func NewSID(addr netip.Addr, structure *SIDStructure) (*SID, error) {
	if !addr.Is6() {
		return nil, fmt.Errorf("SID must be IPv6")
	}
	return &SID{
		Addr:      addr,
		structure: *structure,
	}, nil
}

// MustNewSID is NewSID but panics on error. Should be used only in tests.
func MustNewSID(addr netip.Addr, structure *SIDStructure) *SID {
	sid, err := NewSID(addr, structure)
	if err != nil {
		panic(err)
	}
	return sid
}

// NewSIDFromLFA constructs SID from locator, function and argument parts
func NewSIDFromLFA(l *Locator, f []byte, a []byte) (*SID, error) {
	funcLenBytes := l.structure.FunctionLenBytes()
	argLenBytes := l.structure.ArgumentLenBytes()

	if len(f) != int(funcLenBytes) {
		return nil, fmt.Errorf("function length mismatched with structure")
	}

	if len(a) != int(argLenBytes) {
		return nil, fmt.Errorf("argument length mismatched with structure")
	}

	arr := l.Addr().As16()
	locLenBytes := l.structure.LocatorLenBytes()
	copy(arr[locLenBytes:locLenBytes+funcLenBytes], f)
	copy(arr[locLenBytes+funcLenBytes:locLenBytes+funcLenBytes+argLenBytes], a)

	return &SID{
		Addr:      netip.AddrFrom16(arr),
		structure: l.structure,
	}, nil
}

// MustNewSIDFromLFA is NewSIDFromLFA but panics on error. Should be used only in tests.
func MustNewSIDFromLFA(l *Locator, f []byte, a []byte) *SID {
	sid, err := NewSIDFromLFA(l, f, a)
	if err != nil {
		panic(err)
	}
	return sid
}

// Structure returns a pointer to the SID structure
func (s *SID) Structure() *SIDStructure {
	return &s.structure
}

// AsLocator extracts locator part from SID and return it as a Locator object
func (s *SID) AsLocator() Locator {
	// It's impossible to have invalid locator length (0 or over 128bits)
	// as we already validate it on construction.
	prefix, _ := s.Prefix(int(s.structure.LocatorLenBits()))
	return Locator{
		Prefix:    prefix,
		structure: s.structure,
	}
}

// Locator extracts locator part from SID and return it as a slice
func (s *SID) Locator() []byte {
	arr := s.As16()
	return arr[:s.structure.LocatorLenBytes()]
}

// LocatorBlock extracts locator block part from SID and return it as a slice
func (s *SID) LocatorBlock() []byte {
	arr := s.As16()
	return arr[:s.structure.LocatorBlockLenBytes()]
}

// LocatorNode extracts locator node part from SID and return it as a slice
func (s *SID) LocatorNode() []byte {
	arr := s.As16()
	locBLenBytes := s.structure.LocatorBlockLenBytes()
	locNLenBytes := s.structure.LocatorNodeLenBytes()
	return arr[locBLenBytes : locBLenBytes+locNLenBytes]
}

// Function extracts function part from SID and return it as a slice
func (s *SID) Function() []byte {
	arr := s.As16()
	locLenBytes := s.structure.LocatorLenBytes()
	funcLenBytes := s.structure.FunctionLenBytes()
	return arr[locLenBytes : locLenBytes+funcLenBytes]
}

// Argument extracts argument part from SID and return it as a slice
func (s *SID) Argument() []byte {
	arr := s.As16()
	locLenBytes := s.structure.LocatorLenBytes()
	funcLenBytes := s.structure.FunctionLenBytes()
	argLenBytes := s.structure.ArgumentLenBytes()
	return arr[locLenBytes+funcLenBytes : locLenBytes+funcLenBytes+argLenBytes]
}

// Rest extracts non-SID part and return it as a slice
func (s *SID) Rest() []byte {
	arr := s.As16()
	locLenBytes := s.structure.LocatorLenBytes()
	funcLenBytes := s.structure.FunctionLenBytes()
	argLenBytes := s.structure.ArgumentLenBytes()
	return arr[locLenBytes+funcLenBytes+argLenBytes:]
}

// String returns human-readable string representation of this SID
func (s *SID) String() string {
	return s.Addr.String() + s.structure.String()
}

// This is private and must be accessed through SIDStructure interface
type SIDStructure struct {
	// Locator Block length as described in RFC8986.
	locatorBlockLenBits uint8

	// Locator Node length as described in RFC8986.
	locatorNodeLenBits uint8

	// Function length as described in RFC8986.
	functionLenBits uint8

	// Argument length as described in RFC8986.
	argumentLenBits uint8
}

// Creates new SIDStructure with validation. The validations will be performed
// from RFC and Cilium's perspective. The returned SIDStructure is guaranteed
// to be valid and immutable. Thus, no further validation required for using
// it.
func NewSIDStructure(lb uint8, ln uint8, f uint8, a uint8) (*SIDStructure, error) {
	// Implementation-specific
	//
	// In RFC standard, it is valid to have non-byte-aligned SID structure.
	// However, here we intentionally make such SID structure invalid. This makes
	// SID allocation and datapath processing simpler. This is a practical limitation
	// used in IOS-XR as well.
	//
	// > The length of block [prefix] is defined in bits. From a hardware-friendliness
	// > perspective, it is expected to use sizes on byte boundaries (16, 24, 32, and so on).
	//
	// Ref: https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/segment-routing/73x/b-segment-routing-cg-ncs5500-73x/m-configure-srv6-usid.html
	if lb%8 != 0 || ln%8 != 0 || f%8 != 0 || a%8 != 0 {
		return nil, fmt.Errorf("SID structure bits must be byte-aligned")
	}

	// RFC8986
	if lb+ln+f+a > 128 {
		return nil, fmt.Errorf("total number of bits exceeds 128")
	}

	return &SIDStructure{
		locatorBlockLenBits: lb,
		locatorNodeLenBits:  ln,
		functionLenBits:     f,
		argumentLenBits:     a,
	}, nil
}

// MustNewSIDStructure is NewSIDStructure but panics on error. Should be used only in tests.
func MustNewSIDStructure(lb uint8, ln uint8, f uint8, a uint8) *SIDStructure {
	ss, err := NewSIDStructure(lb, ln, f, a)
	if err != nil {
		panic(err)
	}
	return ss
}

// String return human-readable string representation of this SIDStructure
func (ss *SIDStructure) String() string {
	return fmt.Sprintf("[%d, %d, %d, %d]",
		ss.locatorBlockLenBits, ss.locatorNodeLenBits,
		ss.functionLenBits, ss.argumentLenBits,
	)
}

func (ss *SIDStructure) LocatorLenBits() uint8 {
	return ss.locatorBlockLenBits + ss.locatorNodeLenBits
}

func (ss *SIDStructure) LocatorLenBytes() uint8 {
	return (ss.locatorBlockLenBits + ss.locatorNodeLenBits) / 8
}

func (ss *SIDStructure) LocatorBlockLenBits() uint8 {
	return ss.locatorBlockLenBits
}

func (ss *SIDStructure) LocatorBlockLenBytes() uint8 {
	return ss.locatorBlockLenBits / 8
}

func (ss *SIDStructure) LocatorNodeLenBits() uint8 {
	return ss.locatorNodeLenBits
}

func (ss *SIDStructure) LocatorNodeLenBytes() uint8 {
	return ss.locatorNodeLenBits / 8
}

func (ss *SIDStructure) FunctionLenBits() uint8 {
	return ss.functionLenBits
}

func (ss *SIDStructure) FunctionLenBytes() uint8 {
	return ss.functionLenBits / 8
}

func (ss *SIDStructure) ArgumentLenBits() uint8 {
	return ss.argumentLenBits
}

func (ss *SIDStructure) ArgumentLenBytes() uint8 {
	return ss.argumentLenBits / 8
}

type Behavior uint16

const (
	BehaviorUnknown Behavior = 0
	BehaviorEndDT6  Behavior = 0x0012
	BehaviorEndDT4  Behavior = 0x0013
	BehaviorEndDT46 Behavior = 0x0014
	BehaviorUDT6    Behavior = 0x003E
	BehaviorUDT4    Behavior = 0x003F
	BehaviorUDT46   Behavior = 0x0040
)

// BehaviorFromString RFC8986-compliant string of SRv6 behavior to Behavior constant
func BehaviorFromString(s string) Behavior {
	switch s {
	case "End.DT6":
		return BehaviorEndDT6
	case "End.DT4":
		return BehaviorEndDT4
	case "End.DT46":
		return BehaviorEndDT46
	case "uDT6":
		return BehaviorUDT6
	case "uDT4":
		return BehaviorUDT4
	case "uDT46":
		return BehaviorUDT46
	default:
		return BehaviorUnknown
	}
}

// String converts the behavior to RFC8986-compliant string
func (b Behavior) String() string {
	switch b {
	case BehaviorEndDT6:
		return "End.DT6"
	case BehaviorEndDT4:
		return "End.DT4"
	case BehaviorEndDT46:
		return "End.DT46"
	case BehaviorUDT6:
		return "uDT6"
	case BehaviorUDT4:
		return "uDT4"
	case BehaviorUDT46:
		return "uDT46"
	default:
		return "Unknown"
	}
}

type BehaviorType uint16

const (
	BehaviorTypeUnknown BehaviorType = iota
	BehaviorTypeBase
	BehaviorTypeUSID
)

func BehaviorTypeFromString(s string) BehaviorType {
	switch s {
	case "Base":
		return BehaviorTypeBase
	case "uSID":
		return BehaviorTypeUSID
	default:
		return BehaviorTypeUnknown
	}
}

func BehaviorTypeFromBehavior(b Behavior) BehaviorType {
	switch b {
	case BehaviorEndDT6, BehaviorEndDT4, BehaviorEndDT46:
		return BehaviorTypeBase
	case BehaviorUDT6, BehaviorUDT4, BehaviorUDT46:
		return BehaviorTypeUSID
	default:
		return BehaviorTypeUnknown
	}
}

func (k BehaviorType) String() string {
	switch k {
	case BehaviorTypeBase:
		return "Base"
	case BehaviorTypeUSID:
		return "uSID"
	default:
		return "Unknown"
	}
}
