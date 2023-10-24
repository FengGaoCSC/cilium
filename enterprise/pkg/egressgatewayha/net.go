//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
)

// TODO: Why are we duplicating all this code with OSS?
func getIfaceFirstIPv4Address(ifaceName string) (netip.Addr, error) {
	dev, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}, err
	}

	addrs, err := netlink.AddrList(dev, netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			a, ok := netipx.FromStdIP(addr.IP)
			if !ok {
				continue
			}
			return a, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no IPv4 address assigned to interface")
}

func getIfaceWithIPv4Address(ip netip.Addr) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			a, ok := netipx.FromStdIP(addr.IP)
			if !ok {
				continue
			}
			if a == ip {
				return l.Attrs().Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface with %s IPv4 assigned to", ip)
}
