//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package locatorpool

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/ipam/service/allocator"
)

// LocatorInfo is a combination of Locator and BehaviorType
type LocatorInfo struct {
	types.Locator
	types.BehaviorType
}

type LocatorPool interface {
	GetName() string
	GetPrefix() netip.Prefix

	Allocate(nodeLocator *LocatorInfo) error
	AllocateNext() (*LocatorInfo, error)
	Release(nodeLocator *LocatorInfo) error

	// Free used only for testing
	Free() int
}

const (
	// max node ID is 2^16, so 2 bytes
	maxNodeBits  = 16
	maxNodeBytes = 2
)

type poolConfig struct {
	name         string
	prefix       netip.Prefix
	structure    *types.SIDStructure
	behaviorType string
}

type pool struct {
	config poolConfig

	// byte index in locator prefix where node ID starts and ends
	startIdx uint8
	endIdx   uint8

	// allocated bitmap
	allocator *allocator.AllocationBitmap
}

func newPool(conf poolConfig) (LocatorPool, error) {
	err := validatePool(conf)
	if err != nil {
		return nil, err
	}

	maxAlloc := calculateMax(conf.structure.LocatorLenBits(), uint8(conf.prefix.Bits()))

	p := &pool{
		config:    conf,
		startIdx:  uint8(conf.prefix.Bits() / 8),
		endIdx:    conf.structure.LocatorLenBytes(),
		allocator: allocator.NewAllocationMap(maxAlloc, ""),
	}

	// pre-allocate first ID, this is to avoid using ID 0 for node ID
	_, _ = p.allocator.Allocate(0)
	return p, nil
}

func validatePool(conf poolConfig) error {
	// validate prefix is IPv6
	if !conf.prefix.Addr().Is6() {
		return fmt.Errorf("prefix %q: %s", conf.prefix, ErrInvalidPrefix)
	}

	// Validate prefix is byte aligned, SID structure needs to be byte aligned.
	// This is implementation limitation.
	// https://github.com/isovalent/cilium/blob/9eaa0c516b3d44374bf3addd0e23398767f52c3c/enterprise/pkg/srv6/types/sid.go#L226-L237
	if conf.prefix.Bits()%8 != 0 {
		return fmt.Errorf("prefix %q: %s", conf.prefix, ErrPrefixNotByteAligned)
	}

	// validate  LocB + LocN  > prefix length
	if conf.structure.LocatorLenBits() <= uint8(conf.prefix.Bits()) {
		return ErrInvalidPrefixAndSIDStruct
	}

	// validate LocB <= prefix length
	if conf.structure.LocatorBlockLenBits() > uint8(conf.prefix.Bits()) {
		return ErrInvalidPrefixAndSIDStruct
	}

	if types.BehaviorTypeFromString(conf.behaviorType) == types.BehaviorTypeUnknown {
		return ErrInvalidBehaviorType
	}

	return nil
}

// calculateMax calculates the maximum node ID based on the locator length and prefix length.
// with upper limit of 2^16
func calculateMax(locatorLenBits, prefixLenBits uint8) int {
	nodeBits := locatorLenBits - prefixLenBits
	if nodeBits > maxNodeBits {
		nodeBits = maxNodeBits
	}

	return 1 << nodeBits
}

func (p *pool) GetName() string {
	return p.config.name
}

func (p *pool) GetPrefix() netip.Prefix {
	return p.config.prefix
}

// validNodeLocator validates that node locator was indeed created from this locator pool.
func (p *pool) validNodeLocator(nodeLoc *LocatorInfo) bool {
	// validate both sid structures are same
	if p.config.structure == nil || nodeLoc.Structure() == nil {
		return false
	}

	if *p.config.structure != *nodeLoc.Structure() {
		return false
	}

	if p.config.behaviorType != nodeLoc.BehaviorType.String() {
		return false
	}

	// nodeLocatorPrefix should be equal to SID Locator length
	if nodeLoc.Prefix.Bits() != int(p.config.structure.LocatorLenBits()) {
		return false
	}

	// node locator prefix till pool prefix length should be equal to pool prefix
	expectedPoolPrefix, err := nodeLoc.Prefix.Addr().Prefix(p.config.prefix.Bits())
	if err != nil {
		return false
	}
	if p.config.prefix != expectedPoolPrefix {
		return false
	}

	return true
}

// Allocate calculates node ID from node locator prefix and allocates it if possible
func (p *pool) Allocate(nodeLocator *LocatorInfo) error {
	if !p.validNodeLocator(nodeLocator) {
		return ErrInvalidLocator
	}

	nodeID := int(p.decodeNodeID(nodeLocator.Prefix))

	// check if it is already allocated
	if p.allocator.Has(nodeID) {
		return nil
	}

	ok, _ := p.allocator.Allocate(nodeID)
	if !ok {
		return ErrLocatorAllocation
	}
	return nil
}

func (p *pool) AllocateNext() (*LocatorInfo, error) {
	nodeID, ok, err := p.allocator.AllocateNext()
	if err != nil || !ok {
		return nil, fmt.Errorf("%s: %v", ErrLocatorPoolExhausted, err)
	}

	loc, err := types.NewLocator(
		p.encodeNodeID(uint16(nodeID)),
		p.config.structure,
	)
	if err != nil {
		return nil, err
	}

	return &LocatorInfo{
		Locator:      *loc,
		BehaviorType: types.BehaviorTypeFromString(p.config.behaviorType),
	}, nil
}

func (p *pool) Release(nodeLocator *LocatorInfo) error {
	p.allocator.Release(int(p.decodeNodeID(nodeLocator.Prefix)))
	return nil
}

func (p *pool) decodeNodeID(nodeLocator netip.Prefix) uint16 {
	var nodeID uint16
	nodeIDbytes := make([]byte, maxNodeBytes)
	addr := nodeLocator.Addr().As16()

	// copying of node ID from prefix
	// if available length in prefix is greater than 2 bytes,
	// - copy last 2 bytes from available space [endIdx-maxNodeBytes:endIdx]
	// if available length in prefix is less than 2 bytes
	// - copy bytes equal to available length from prefix [startIdx:endIdx]
	// - while transferring bytes to nodeIDbytes, start from maxNodeBytes - (endIdx - startIdx)

	if p.endIdx-p.startIdx > maxNodeBytes {
		copy(nodeIDbytes, addr[p.endIdx-maxNodeBytes:p.endIdx])
	} else {
		copy(nodeIDbytes[maxNodeBytes-(p.endIdx-p.startIdx):], addr[p.startIdx:p.endIdx])
	}
	nodeID = binary.BigEndian.Uint16(nodeIDbytes)

	return nodeID
}

func (p *pool) encodeNodeID(nodeID uint16) netip.Prefix {
	// embed node ID bytes into locator prefix
	nodeIDBytes := make([]byte, maxNodeBytes)
	binary.BigEndian.PutUint16(nodeIDBytes, nodeID)

	// max node ID space is 2 bytes,
	// if available length in prefix is greater than 2 bytes,
	// - we need to copy all node bytes
	// if available length in prefix is less than 2 bytes,
	// - we need to copy bytes equal to available length

	addr := p.config.prefix.Addr().As16()
	if p.endIdx-p.startIdx > maxNodeBytes {
		copy(addr[p.startIdx:p.endIdx], nodeIDBytes)
	} else {
		copy(addr[p.startIdx:p.endIdx], nodeIDBytes[maxNodeBytes-(p.endIdx-p.startIdx):])
	}

	return netip.PrefixFrom(netip.AddrFrom16(addr), int(p.config.structure.LocatorLenBits()))
}

// internal state for testing

// Free returns number of free IDs in the pool
func (p *pool) Free() int {
	return p.allocator.Free()
}
