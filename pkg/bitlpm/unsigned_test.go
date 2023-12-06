package bittrie

import (
	"fmt"
	"math/bits"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type uint16Range struct {
	start, end uint16
}

func (pr uint16Range) prefix() uint {
	return prefixFromRange(pr.start, max(pr.end, pr.start))
}

func prefixFromRange(start, end uint16) uint {
	return 16 - uint(bits.TrailingZeros16(^uint16(end-start)))
}

func (pr uint16Range) String() string {
	return fmt.Sprintf("%d-%d", pr.start, pr.end)
}

var uint16RangeMap = map[uint]uint16{
	0:  0b1111_1111_1111_1111,
	1:  0b111_1111_1111_1111,
	2:  0b11_1111_1111_1111,
	3:  0b1_1111_1111_1111,
	4:  0b1111_1111_1111,
	5:  0b111_1111_1111,
	6:  0b11_1111_1111,
	7:  0b1_1111_1111,
	8:  0b1111_1111,
	9:  0b111_1111,
	10: 0b11_1111,
	11: 0b1_1111,
	12: 0b1111,
	13: 0b111,
	14: 0b11,
	15: 0b1,
	16: 0,
}

func endFromPrefix(prefix uint, start uint16) uint16 {
	return start + uint16RangeMap[prefix]
}

var (
	uint16Range65535 = []uint16Range{
		{start: 65535, end: 65535},
	}
	uint16Range0_65535 = []uint16Range{
		{start: 0, end: 65535},
	}
	uint16Range1_65534 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
		{start: 8, end: 15},
		{start: 16, end: 31},
		{start: 32, end: 63},
		{start: 64, end: 127},
		{start: 128, end: 255},
		{start: 256, end: 511},
		{start: 512, end: 1023},
		{start: 1024, end: 2047},
		{start: 2048, end: 4095},
		{start: 4096, end: 8191},
		{start: 8192, end: 16383},
		{start: 16384, end: 32767},
		{start: 32768, end: 49151},
		{start: 49152, end: 57343},
		{start: 57344, end: 61439},
		{start: 61440, end: 63487},
		{start: 63488, end: 64511},
		{start: 64512, end: 65023},
		{start: 65024, end: 65279},
		{start: 65280, end: 65407},
		{start: 65408, end: 65471},
		{start: 65472, end: 65503},
		{start: 65504, end: 65519},
		{start: 65520, end: 65527},
		{start: 65528, end: 65531},
		{start: 65532, end: 65533},
		{start: 65534, end: 65534},
	}
	uint16Range0_1023 = []uint16Range{
		{start: 0, end: 1023},
	}
	uint16Range1_1023 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
		{start: 8, end: 15},
		{start: 16, end: 31},
		{start: 32, end: 63},
		{start: 64, end: 127},
		{start: 128, end: 255},
		{start: 256, end: 511},
		{start: 512, end: 1023},
	}
	uint16Range0_7 = []uint16Range{
		{start: 0, end: 7},
	}
	uint16Range1_7 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
	}
	uint16Range0_1 = []uint16Range{
		{start: 0, end: 1},
	}
	uint16Range1_1 = []uint16Range{
		{start: 1, end: 1},
	}
)

// TestUnsignedUpdate tests to see that a trie contains
// all the values it should after every update.
func TestUnsignedUpdate(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%d_%d%s", tt.ranges[0].start,
			tt.ranges[len(tt.ranges)-1].end, tt.name)
		// Check that the whole trie is what it should be
		// on each update.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for i, pr := range tt.ranges {
				ut.Update(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
				var got []uint16Range
				ut.ForEach(ForEachFunc[uint16, string](func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				}))
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[:i+1]) {
					t.Fatalf("When updating an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[:i+1])
				}
			}
		})
	}
}

// TestUnsignedLookup looks up every possible value expressed
// in a trie structure by the most specific prefix.
func TestUnsignedLookup(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		firstRange := tt.ranges[0]
		lastRange := tt.ranges[len(tt.ranges)-1]
		name := fmt.Sprintf("%d_%d%s", firstRange.start, lastRange.end, tt.name)
		// Check that every valid key returns the correct
		// entry and every invalid key returns nothing.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Update(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for _, pr := range tt.ranges {
				entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
				start := pr.start
				end := pr.end
				// uint16 should be converted to uint for the
				// purpose of the loop condition as some tests
				// overflow uint16 causing an infinite loop.
				for p := uint(start); p <= uint(end); p++ {
					got := ut.Lookup(16, uint16(p))
					if entry != got {
						t.Fatalf("Looking up key %d, expected entry %q, but got %q", p, entry, got)
					}
				}
			}
			// look up all the missing keys.
			start := firstRange.start
			end := lastRange.end
			for p := uint(0); p < uint(start); p++ {
				got := ut.Lookup(16, uint16(p))
				if got != "" {
					t.Fatalf("Looking up key %d, expected no entry, but got %q", p, got)
				}
			}
			for p := uint(end) + 1; p <= uint(65535); p++ {
				got := ut.Lookup(16, uint16(p))
				if got != "" {
					t.Fatalf("Looking up key %d, expected no entry, but got %q", p, got)
				}
			}
		})
	}
}

// TestUnsignedLookupDynamicPrefix tests looking up keys with
// a non-full prefix (i.e. a range of keys), by creating tries
// in different ranges and ensuring that the trie returns
// in-range queries from other known in-range lookups, and that
// known out-of-range lookups fail.
func TestUnsignedLookupDynamicPrefix(t *testing.T) {
	ranges := [][]uint16Range{
		uint16Range65535,
		uint16Range0_65535,
		uint16Range1_65534,
		uint16Range0_1023,
		uint16Range1_1023,
		uint16Range0_7,
		uint16Range1_7,
		uint16Range0_1,
		uint16Range1_1,
	}
	// eliminate duplicate range lookups
	rangeLookupMap := make(map[string]uint16Range)
	for _, r := range ranges {
		for _, pr := range r {
			entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
			if _, ok := rangeLookupMap[entry]; !ok {
				rangeLookupMap[entry] = pr
			}
		}
	}
	for _, r := range ranges {
		rangeStart := r[0].start
		rangeEnd := r[len(r)-1].end
		name := fmt.Sprintf("%d_%d", rangeStart, rangeEnd)
		t.Run(name, func(t *testing.T) {
			tu := NewUintTrie[uint16, string]()
			for _, pr := range r {
				entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
				tu.Update(pr.prefix(), pr.start, entry)
			}
			for _, pr := range rangeLookupMap {
				gotEntry := tu.Lookup(pr.prefix(), pr.start)
				if pr.start < rangeStart || pr.end > rangeEnd {
					if gotEntry != "" {
						t.Fatalf("Expected to get an emty entry from key-prefix %d/%d, got %q",
							pr.start, pr.prefix(), gotEntry)
					}
				} else {
					if gotEntry == "" {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got no entry",
							pr.start, pr.prefix())
					}
					rangeS := strings.Split(gotEntry, "-")
					start, err := strconv.ParseUint(rangeS[0], 10, 16)
					if err != nil {
						t.Fatalf("Error parsing start value of range entry %q", gotEntry)
					}
					if uint16(start) > pr.start {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got %q",
							pr.start, pr.prefix(), gotEntry)
					}
					end, err := strconv.ParseUint(rangeS[1], 10, 16)
					if err != nil {
						t.Fatalf("Error parsing end value of range entry %q", gotEntry)
					}
					if uint16(end) < pr.end {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got %q",
							pr.start, pr.prefix(), gotEntry)
					}
				}
			}
		})
	}
}

// TestUnsignedDelete creates a trie from a set of ranges
// and then incrementally deletes each entry, checking
// that the trie contains all the values it should after
// each delete. It checks deleting the trie both
// from the bottom of a range up, and the top of the range
// down.
func TestUnsignedDelete(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%d_%d%s", tt.ranges[0].start,
			tt.ranges[len(tt.ranges)-1].end, tt.name)
		// Check that the whole trie is what it should be
		// on each deletion in order.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Update(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for i, pr := range tt.ranges {
				// The "got" slice cannot be nil for the DeepEqual
				// comparison, even if it is empty.
				got := make([]uint16Range, 0, len(tt.ranges)-i-1)
				ok := ut.Delete(pr.prefix(), pr.start)
				if !ok {
					t.Fatalf("Key-prefix %d/%d not deleted", pr.start, pr.prefix())
				}
				ut.ForEach(ForEachFunc[uint16, string](func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				}))
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[i+1:]) {
					t.Fatalf("When deleting an entry from an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[i+1:])
				}
			}
		})
		// Delete in reverse order.
		t.Run(fmt.Sprintf("In_Reverse_%s", name), func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Update(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for i := len(tt.ranges) - 1; i >= 0; i-- {
				pr := tt.ranges[i]
				// The "got" slice cannot be nil for the DeepEqual
				// comparison, even if it is empty.
				got := make([]uint16Range, 0, i+1)
				ok := ut.Delete(pr.prefix(), pr.start)
				if !ok {
					t.Fatalf("Key-prefix %d/%d not deleted", pr.start, pr.prefix())
				}
				ut.ForEach(ForEachFunc[uint16, string](func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				}))
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[:i]) {
					t.Fatalf("When deleting an entry from an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[:i])
				}
			}
		})
	}
}
