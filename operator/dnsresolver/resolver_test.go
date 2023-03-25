// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/operator/dnsclient"
)

type mockStore struct {
	setFn func(fqdn string, prefixes []netip.Prefix)
}

func (s *mockStore) set(fqdn string, prefixes []netip.Prefix) {
	s.setFn(fqdn, prefixes)
}

func TestResolver(t *testing.T) {
	defer goleak.VerifyNone(t)

	done := make(chan struct{})

	// create a mock dns client
	ipv4Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		if fqdn != "cilium.io" {
			return nil, nil, fmt.Errorf("unable to resolve fqdn %q", fqdn)
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, []time.Duration{0}, nil
	}
	ipv6Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::68")}, []time.Duration{0}, nil
	}
	client := &mockClient{ipv4Fn, ipv6Fn}

	// create a mock fqdn store
	var storeErr error
	setFn := func(fqdn string, prefixes []netip.Prefix) {
		// signal the main goroutine that the set operation has been called.
		// This callback might be called more than once, in that case we should
		// not close the channel twice.
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()

		if fqdn != "cilium.io" {
			storeErr = fmt.Errorf("expected fqdn %q to be set, got %q", "cilium.io", fqdn)
			return
		}
		expected := []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("2001:db8::68/128")}
		if !reflect.DeepEqual(prefixes, expected) {
			storeErr = fmt.Errorf("expected prefixes %v for fqdn %q, got %v", expected, "cilium.io", prefixes)
			return
		}
	}
	store := &mockStore{setFn}

	// create a test logger
	logger, _ := test.NewNullLogger()

	resolver := newResolver(logger, "cilium.io", "test-group", client, time.Second, store)

	if err := resolver.run(); err != nil {
		t.Fatalf("resolver run failed: %v", err)
	}

	// wait for store set to be called
	<-done

	if err := resolver.close(); err != nil {
		t.Fatalf("resolver close failed: %v", err)
	}

	if storeErr != nil {
		t.Fatalf("unexpected error from fqdn store: %s", storeErr)
	}
}

func TestResolverNonExistentDomain(t *testing.T) {
	defer goleak.VerifyNone(t)

	done := make(chan struct{})

	// create a mock dns client
	ipv4Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		if fqdn != "cilium.io" {
			return nil, nil, fmt.Errorf("unable to resolve fqdn %q", fqdn)
		}
		return nil, nil, dnsclient.ErrNonExistentDomain
	}
	ipv6Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return nil, nil, nil
	}
	client := &mockClient{ipv4Fn, ipv6Fn}

	// create a mock fqdn store
	var storeErr error
	setFn := func(fqdn string, prefixes []netip.Prefix) {
		// signal the main goroutine that the set operation has been called.
		// This callback might be called more than once, in that case we should
		// not close the channel twice.
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()

		if fqdn != "cilium.io" {
			storeErr = fmt.Errorf("expected fqdn %q to be set, got %q", "cilium.io", fqdn)
			return
		}
		// cache should be cleared in case of a NXDOMAIN error from DNS server
		if prefixes != nil {
			storeErr = fmt.Errorf("expected prefixes to be nil for fqdn %q, got %v", "cilium.io", prefixes)
			return
		}
	}
	store := &mockStore{setFn}

	// create a test logger
	logger, _ := test.NewNullLogger()

	resolver := newResolver(logger, "cilium.io", "test-group", client, time.Second, store)

	if err := resolver.run(); err != nil {
		t.Fatalf("resolver run failed: %v", err)
	}

	// wait for store set to be called
	<-done

	if err := resolver.close(); err != nil {
		t.Fatalf("resolver close failed: %v", err)
	}

	if storeErr != nil {
		t.Fatalf("unexpected error from fqdn store: %s", storeErr)
	}
}

func TestResolverQueryError(t *testing.T) {
	defer goleak.VerifyNone(t)

	done := make(chan struct{})

	// create a mock dns client
	retries := 0
	ipv4Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		// signal the main goroutine that the query operation has been retried
		// at least 2 times.
		// This callback might be retried even more times, in that case we should
		// not close the channel twice.
		defer func() {
			if retries < 2 {
				return
			}
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		retries++
		return nil, nil, errors.New("DNS query error")
	}
	ipv6Fn := func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return nil, nil, nil
	}
	client := &mockClient{ipv4Fn, ipv6Fn}

	// create a mock fqdn store
	var storeErr error
	setFn := func(fqdn string, prefixes []netip.Prefix) {
		// cache should NOT be cleared in case of an error different from NXDOMAIN
		storeErr = fmt.Errorf("unexpected call to store set: fqdn %q prefixes %v", fqdn, prefixes)
	}
	store := &mockStore{setFn}

	// create a test logger
	logger, _ := test.NewNullLogger()

	resolver := newResolver(logger, "cilium.io", "test-group", client, time.Second, store)

	if err := resolver.run(); err != nil {
		t.Fatalf("resolver run failed: %v", err)
	}

	// wait for query to be retried at least 2 times
	<-done

	if err := resolver.close(); err != nil {
		t.Fatalf("resolver close failed: %v", err)
	}

	if storeErr != nil {
		t.Fatalf("unexpected error from fqdn store: %s", storeErr)
	}
}
