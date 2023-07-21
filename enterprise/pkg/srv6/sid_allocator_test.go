//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"

	"github.com/stretchr/testify/require"
)

func TestStructuredSIDAllocator(t *testing.T) {
	locator := types.MustNewLocator(
		netip.MustParsePrefix("fd00::/64"),
		types.MustNewSIDStructure(48, 16, 16, 0),
	)

	t.Run("TestAllocate", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator)
		require.NoError(t, err)

		// Valid allocation
		sid, err := allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Equal(t, sid.Addr, netip.MustParseAddr("fd00:0:0:0:1::"))
		require.Equal(t, *sid.Structure(), *types.MustNewSIDStructure(48, 16, 16, 0))

		// Cannot allocate duplicated SID
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Locator mismatch
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:1:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Zero function part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Non-zero rest part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::1"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)
	})

	t.Run("TestAllocateNext", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator)
		require.NoError(t, err)

		// Valid allocation
		sid, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Len(t, sid.Function(), 2)
		require.NotEqual(t, []byte{0, 0}, sid.Function())
	})

	t.Run("TestRelease", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator)
		require.NoError(t, err)

		// Valid release
		sid, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(sid.Addr)
		require.NoError(t, err)

		// Released SID should be reallocatable
		sid, err = allocator.Allocate(sid.Addr, "test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(sid.Addr)
		require.NoError(t, err)
	})

	t.Run("TestAllocatedSIDs", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator)
		require.NoError(t, err)

		// Getting specific owner's SIDs
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids := allocator.AllocatedSIDs("test1")
		require.Len(t, sids, 1)
		require.Equal(t, "test1", sids[0].Owner)
		require.Equal(t, "key1", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:0:1::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "test2", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids = allocator.AllocatedSIDs("test2")
		require.Len(t, sids, 1)
		require.Equal(t, "test2", sids[0].Owner)
		require.Equal(t, "key2", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:0:2::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		// Getting all SIDs
		sids = allocator.AllocatedSIDs("")
		require.Len(t, sids, 2)
	})
}
