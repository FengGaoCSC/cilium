// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusDeepCopy(t *testing.T) {
	testcases := [...]struct {
		name     string
		status   status
		expected status
	}{
		{
			name:   "nil status",
			status: nil,
		},
		{
			name: "non-nil status",
			status: status{
				"fqdn-group-1": nil,
				"fqdn-group-2": {},
				"fqdn-group-3": {"ebpf.io", "cilium.io"},
			},
			expected: status{
				"fqdn-group-1": nil,
				"fqdn-group-2": {},
				"fqdn-group-3": {"ebpf.io", "cilium.io"},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.status.deepCopy())
		})
	}
}

func TestStatusDiff(t *testing.T) {
	testcases := [...]struct {
		name          string
		status        status
		other         status
		expectedNew   []string
		expectedStale []string
	}{
		{
			name:          "nil",
			status:        status{},
			other:         status{},
			expectedNew:   nil,
			expectedStale: nil,
		},
		{
			name: "empty",
			status: status{
				"fqdn-group-1": {},
			},
			other: status{
				"fqdn-group-1": {},
			},
			expectedNew:   nil,
			expectedStale: nil,
		},
		{
			name: "equal",
			status: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			other: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			expectedNew:   nil,
			expectedStale: nil,
		},
		{
			name:   "all new",
			status: status{},
			other: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			expectedNew:   []string{"cilium.io", "isovalent.com", "ebpf.io"},
			expectedStale: nil,
		},
		{
			name: "all stale",
			status: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			other:         status{},
			expectedNew:   nil,
			expectedStale: []string{"cilium.io", "isovalent.com", "ebpf.io"},
		},
		{
			name: "subset",
			status: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			other: status{
				"fqdn-group-1": {"cilium.io", "ebpf.io"},
				"fqdn-group-2": {},
			},
			expectedNew:   nil,
			expectedStale: []string{"isovalent.com"},
		},
		{
			name: "superset",
			status: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"isovalent.com"},
			},
			other: status{
				"fqdn-group-1": {"cilium.io", "isovalent.com", "google.com", "ebpf.io"},
				"fqdn-group-2": {"microsoft.com"},
				"fqdn-group-3": {"isovalent.com"},
				"fqdn-group-4": {"facebook.com"},
			},
			expectedNew:   []string{"google.com", "microsoft.com", "facebook.com"},
			expectedStale: nil,
		},
		{
			name: "new and stale",
			status: status{
				"fqdn-group-1": {"cilium.io", "ebpf.io"},
				"fqdn-group-2": {},
				"fqdn-group-3": {"ebpf.io"},
			},
			other: status{
				"fqdn-group-1": {"cilium.io"},
				"fqdn-group-2": {"isovalent.com"},
			},
			expectedNew:   []string{"isovalent.com"},
			expectedStale: []string{"ebpf.io"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			new, stale := tc.status.diff(tc.other)
			assert.ElementsMatch(t, new, tc.expectedNew)
			assert.ElementsMatch(t, stale, tc.expectedStale)
		})
	}
}
