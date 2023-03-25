// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"net/netip"
	"time"
)

func retry(check func() error) error {
	wait := 10 * time.Millisecond

	for {
		time.Sleep(wait)
		if err := check(); err == nil {
			return nil
		}
		wait *= 2
	}
}

type mockClient struct {
	ipv4Fn func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)
	ipv6Fn func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)
}

func (c *mockClient) QueryIPv4(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.ipv4Fn(ctx, fqdn)
}

func (c *mockClient) QueryIPv6(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.ipv6Fn(ctx, fqdn)
}
