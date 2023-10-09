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
	"net"

	"github.com/vishvananda/netlink"
)

func getIfaceFirstIPv4Address(ifaceName string) (net.IPNet, error) {
	dev, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return net.IPNet{}, err
	}

	addrs, err := netlink.AddrList(dev, netlink.FAMILY_V4)
	if err != nil {
		return net.IPNet{}, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			return *addr.IPNet, nil
		}
	}

	return net.IPNet{}, fmt.Errorf("no IPv4 address assigned to interface")
}

func getIfaceWithIPv4Address(ip net.IP) (string, net.IPMask, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", nil, err
	}

	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return "", nil, err
		}

		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return l.Attrs().Name, addr.Mask, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no interface with %s IPv4 assigned to", ip)
}
