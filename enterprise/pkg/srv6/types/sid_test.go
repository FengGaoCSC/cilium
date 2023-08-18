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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewSIDStructure(t *testing.T) {
	tests := []struct {
		name      string
		lb        uint8
		ln        uint8
		f         uint8
		a         uint8
		structure SIDStructure
		errorStr  string
	}{
		{
			name: "ValidStructureF3216",
			lb:   32, ln: 16, f: 16, a: 0,
			structure: SIDStructure{32, 16, 16, 0},
		},
		{
			name: "ValidStructureCiliumLegacy",
			lb:   128, ln: 0, f: 0, a: 0,
			structure: SIDStructure{128, 0, 0, 0},
		},
		{
			name: "NonByteAlignedLocatorBlock",
			lb:   33, ln: 16, f: 16, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "NonByteAlignedLocatorNode",
			lb:   32, ln: 17, f: 16, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "NonByteAlignedFunction",
			lb:   32, ln: 16, f: 17, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "Over128Bit",
			lb:   64, ln: 64, f: 32, a: 0,
			errorStr: "total number of bits exceeds 128",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ss, err := NewSIDStructure(test.lb, test.ln, test.f, test.a)
			if test.errorStr != "" {
				require.Error(t, err)
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.structure, *ss)
			}
		})
	}
}

func TestNewLocator(t *testing.T) {
	tests := []struct {
		name      string
		prefix    netip.Prefix
		structure SIDStructure
		locator   Locator
		errorStr  string
	}{
		{
			name:      "ValidLocator",
			prefix:    netip.MustParsePrefix("fd00::/48"),
			structure: SIDStructure{32, 16, 16, 0},
			locator: Locator{
				Prefix:    netip.MustParsePrefix("fd00::/48"),
				structure: *MustNewSIDStructure(32, 16, 16, 0),
			},
		},
		{
			name:      "InvalidPrefix",
			prefix:    netip.MustParsePrefix("10.0.0.0/24"),
			structure: SIDStructure{32, 16, 16, 0},
			errorStr:  "locator prefix must be IPv6",
		},
		{
			name:      "PrefixStructureBitsMismatch",
			prefix:    netip.MustParsePrefix("fd00::/48"),
			structure: SIDStructure{48, 16, 16, 0},
			errorStr:  "locator prefix length (48) doesn't match with structure (64)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l, err := NewLocator(test.prefix, &test.structure)
			if test.errorStr != "" {
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.locator, *l)
			}
		})
	}
}

func TestNewSID(t *testing.T) {
	tests := []struct {
		name      string
		addr      netip.Addr
		structure SIDStructure
		sid       SID
		errorStr  string
	}{
		{
			name:      "ValidSID",
			addr:      netip.MustParseAddr("fd00::"),
			structure: SIDStructure{32, 16, 16, 0},
			sid: SID{
				Addr:      netip.MustParseAddr("fd00::"),
				structure: SIDStructure{32, 16, 16, 0},
			},
		},
		{
			name:      "InvalidAddr",
			addr:      netip.MustParseAddr("10.0.0.0"),
			structure: SIDStructure{32, 16, 16, 0},
			sid:       SID{},
			errorStr:  "SID must be IPv6",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sid, err := NewSID(test.addr, &test.structure)
			if test.errorStr != "" {
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.sid, *sid)
			}
		})
	}
}
