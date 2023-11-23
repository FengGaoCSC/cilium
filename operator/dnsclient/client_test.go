// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsclient

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/goleak"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

func typeA(w dns.ResponseWriter, req *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Ttl:    1,
		},
		A: net.ParseIP("1.1.1.1"),
	}
	w.WriteMsg(m)
}

func typeAAAA(w dns.ResponseWriter, req *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeAAAA,
			Ttl:    1,
		},
		AAAA: net.ParseIP("2001:db8::68"),
	}
	w.WriteMsg(m)
}

func server(
	ipv4Fn func(dns.ResponseWriter, *dns.Msg),
	ipv6Fn func(dns.ResponseWriter, *dns.Msg),
) (*dns.Server, net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		return nil, nil, err
	}

	mux := dns.NewServeMux()
	mux.Handle("ipv4.com", dns.HandlerFunc(ipv4Fn))
	mux.Handle("ipv6.com", dns.HandlerFunc(ipv6Fn))

	return &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}, pc, nil
}

func TestClient(t *testing.T) {
	defer goleak.VerifyNone(t)

	var client Resolver

	srv, conn, err := server(typeA, typeAAAA)
	if err != nil {
		t.Fatalf("DNS test server creation failed: %s", err)
	}

	hive := hive.New(
		cell.Provide(func() Config {
			return Config{
				DNSServerAddresses: []string{conn.LocalAddr().String()},
			}
		}),
		cell.Provide(func() bool {
			// enable dnsclient metrics
			return true
		}),

		cell.Provide(newClient),

		cell.Invoke(func(lc hive.Lifecycle) error {
			lc.Append(hive.Hook{
				OnStart: func(ctx hive.HookContext) error {
					go srv.ActivateAndServe()
					return nil
				},
				OnStop: func(ctx hive.HookContext) error {
					return srv.ShutdownContext(ctx)
				},
			})
			return nil
		}),
		cell.Invoke(func() {
			operatorMetrics.Registry = prometheus.NewPedanticRegistry()
		}),
		cell.Invoke(func(r Resolver) {
			client = r
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	testIPv4(t, client)
	testIPv6(t, client)

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func testIPv4(t *testing.T, client Resolver) {
	ips, ttls, err := client.QueryIPv4(context.Background(), "ipv4.com")
	if err != nil {
		t.Fatalf("error while querying DNS server: %s", err)
	}

	if err := checkIPs([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, ips); err != nil {
		t.Fatal(err)
	}
	if err := checkTTLs([]time.Duration{time.Second}, ttls); err != nil {
		t.Fatal(err)
	}
}

func testIPv6(t *testing.T, client Resolver) {
	ips, ttls, err := client.QueryIPv6(context.Background(), "ipv6.com")
	if err != nil {
		t.Fatalf("error while querying DNS server: %s", err)
	}

	if err := checkIPs([]netip.Addr{netip.MustParseAddr("2001:db8::68")}, ips); err != nil {
		t.Fatal(err)
	}
	if err := checkTTLs([]time.Duration{time.Second}, ttls); err != nil {
		t.Fatal(err)
	}
}

func checkIPs(expected []netip.Addr, got []netip.Addr) error {
	if len(expected) != len(got) {
		return fmt.Errorf("expected %d IPs, got %v", len(expected), len(got))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != got[i] {
			return fmt.Errorf("expected IP %v, got %v", expected[i], got[i])
		}
	}
	return nil
}

func checkTTLs(expected []time.Duration, got []time.Duration) error {
	if len(expected) != len(got) {
		return fmt.Errorf("expected %d TTLs, got %v", len(expected), len(got))
	}
	// We have to take into account the (unpredictable) RTT time,
	// so we consider acceptable a value that is in the range
	// [50% of expected TTL, 150% of expected TTL]
	for i := 0; i < len(expected); i++ {
		lowerLimit := time.Duration(float64(expected[i]) * 0.5)
		upperLimit := time.Duration(float64(expected[i]) * 1.5)
		if expected[i] < lowerLimit || expected[i] > upperLimit {
			return fmt.Errorf("expected value to be in [%v, %v], got %v", lowerLimit, upperLimit, expected[i])
		}
	}
	return nil
}
