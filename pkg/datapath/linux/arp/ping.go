// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package arp

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrL2Unreachable  = errors.New("interface can't reach the IP address")

	timeout = 1 * time.Second
)

var defaultSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// PingOverIface performs arping request to the 'dst' IP address over the 'iface' and
// returns the hardware address (MAC) of the destination if it is reachable
func PingOverIface(iface net.Interface, dst net.IP) (net.HardwareAddr, error) {
	src, err := findSourceIP(iface, dst)
	if err != nil {
		return nil, err
	}

	p, err := newPinger(&iface, src)
	if err != nil {
		return nil, err
	}
	defer p.close()

	if err := p.setDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	return p.resolve(dst)
}

var _ net.Addr = &Addr{}

type Addr struct {
	net.HardwareAddr
}

func (a *Addr) Network() string {
	return "raw"
}

type pinger struct {
	c     net.PacketConn
	ip    net.IP
	iface *net.Interface
}

func (p *pinger) close() {
	_ = p.c.Close()
}

func (p *pinger) setDeadline(t time.Time) error {
	return p.c.SetDeadline(t)
}

func (p *pinger) resolve(ip net.IP) (net.HardwareAddr, error) {
	if err := p.request(ip); err != nil {
		return nil, err
	}

	for {
		resp, err := p.read()
		if err != nil {
			return nil, err
		}

		if resp.Operation != layers.ARPReply || !bytes.Equal(resp.SourceProtAddress, []byte(ip.To4())) {
			continue
		}

		return resp.SourceHwAddress, nil
	}
}

func (p *pinger) read() (*layers.ARP, error) {
	buf := make([]byte, 128)
	for {
		n, _, err := p.c.ReadFrom(buf)
		if err != nil {
			return nil, err
		}

		arp, err := decodeARPReply(buf, n)
		if err != nil {
			return nil, err
		}

		if arp.Protocol != layers.EthernetTypeIPv4 || arp.ProtAddressSize != 4 {
			continue
		}

		return arp, nil
	}
}

func (p *pinger) request(ip net.IP) error {
	req, err := newARPRequest(p.iface.HardwareAddr, p.ip, layers.EthernetBroadcast, ip)
	if err != nil {
		return err
	}

	_, err = p.c.WriteTo(req, &Addr{HardwareAddr: layers.EthernetBroadcast})

	return err
}

func newPinger(iface *net.Interface, ip net.IP) (*pinger, error) {
	c, err := listen(iface)
	if err != nil {
		return nil, err
	}

	return &pinger{
		c:     c,
		iface: iface,
		ip:    ip,
	}, nil
}

func decodeARPReply(buf []byte, n int) (*layers.ARP, error) {
	ethernet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Default)

	arp := &layers.ARP{}
	arpLayer := ethernet.Layer(layers.LayerTypeARP)
	if err := arp.DecodeFromBytes(arpLayer.LayerContents(), gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	return arp, nil
}

func findSourceIP(iface net.Interface, dst net.IP) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(dst) {
			return ipnet.IP, nil
		}
	}

	return nil, ErrL2Unreachable
}

func newARPRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
	}

	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:   6,
		ProtAddressSize: 4,
		Operation:       layers.ARPRequest,

		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),

		DstHwAddress:   []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOpts, &ether, &arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
