// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmapha

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ebpf"
)

// ApplyEgressPolicy adds a new entry to the egress policy map.
// If a policy with the same key already exists, it will get replaced.
func ApplyEgressPolicy(policyMap PolicyMap, sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, activeGatewayIPs []netip.Addr) error {
	if len(activeGatewayIPs) > maxGatewayNodes {
		return fmt.Errorf("cannot apply egress policy: too many gateways")
	}

	if err := policyMap.Update(sourceIP, destCIDR, egressIP, activeGatewayIPs); err != nil {
		return fmt.Errorf("cannot apply egress policy: %w", err)
	}

	return nil
}

// RemoveEgressPolicy removes an egress policy identified by the (source IP,
// destination CIDR) tuple.
// In addition to removing the policy, this function removes also all CT entries
// from the egress CT map which match the egress policy.
func RemoveEgressPolicy(policyMap PolicyMap, sourceIP netip.Addr, destCIDR netip.Prefix) error {
	_, err := policyMap.Lookup(sourceIP, destCIDR)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("egress policy does not exist")
		}

		return fmt.Errorf("cannot lookup egress policy: %w", err)
	}

	if err := policyMap.Delete(sourceIP, destCIDR); err != nil {
		return err
	}

	return nil
}
