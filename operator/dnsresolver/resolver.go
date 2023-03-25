// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	"github.com/cilium/cilium/operator/dnsclient"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// resolver encapsulates a dns client and periodically resolves the given fqdn,
// send the ips from the dns response to the store.
type resolver struct {
	logger logrus.FieldLogger

	fqdn string

	client     dnsclient.Resolver
	minWait    time.Duration
	expBackoff backoff.Exponential

	store store

	wp *workerpool.WorkerPool
}

func newResolver(
	logger logrus.FieldLogger,
	fqdn string,
	fqdnGroup string,
	client dnsclient.Resolver,
	minWait time.Duration,
	store store,
) *resolver {
	return &resolver{
		logger: logger.WithFields(logrus.Fields{
			"fqdn":          fqdn,
			"fromFQDNGroup": fqdnGroup,
		}),
		fqdn:    fqdn,
		client:  client,
		minWait: minWait,
		expBackoff: backoff.Exponential{
			Min:  minWait,
			Max:  5 * time.Minute,
			Name: "fqdn-resolver-" + fqdn,
		},
		store: store,
		wp:    workerpool.New(1),
	}
}

func (r *resolver) run() error {
	r.logger.Debug("resolver started")

	return r.wp.Submit(
		"fqdn-resolver-"+r.fqdn,
		r.resolve,
	)
}

func (r *resolver) close() error {
	r.logger.Debug("resolver stopped")
	return r.wp.Close()
}

func (r *resolver) resolve(ctx context.Context) error {
	timer := time.NewTimer(r.minWait)
	defer func() {
		if !timer.Stop() {
			// be sure to drain the timer channel if it
			// expires before the call to Stop.
			<-timer.C
		}
	}()

	for {
		var (
			ips      []netip.Addr
			ttls     []time.Duration
			attempts int
			err      error
		)

	stop:
		for {
			ips, ttls, err = query(ctx, r.client, r.fqdn)
			switch {
			case err == nil:
				break stop
			case errors.Is(err, context.Canceled):
				return nil
			case errors.Is(err, dnsclient.ErrNonExistentDomain):
				// in case of a NXDOMAIN error we clear the cache
				r.store.set(r.fqdn, nil)
			}

			attempts++
			r.logger.WithField(logfields.Interval, r.expBackoff.Duration(attempts)).WithError(err).
				Warning("DNS resolution failed for IsovalentFQDNGroup, retrying after backoff interval")

			r.expBackoff.Wait(ctx)
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
		}

		r.expBackoff.Reset()

		prefixes := make([]netip.Prefix, 0, len(ips))
		for _, ip := range ips {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
		r.store.set(r.fqdn, prefixes)

		interval := r.minWait
		if len(ttls) > 0 {
			next := minTTL(ttls)
			if next > interval {
				interval = next
			}
		}

		timer.Reset(interval)
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}

func query(ctx context.Context, client dnsclient.Resolver, fqdn string) ([]netip.Addr, []time.Duration, error) {
	ipsv4, ttlsv4, errv4 := client.QueryIPv4(ctx, fqdn)
	if errors.Is(errv4, context.Canceled) || errors.Is(errv4, dnsclient.ErrNonExistentDomain) {
		return nil, nil, errv4
	}

	ipsv6, ttlsv6, errv6 := client.QueryIPv6(ctx, fqdn)
	if errors.Is(errv6, context.Canceled) || errors.Is(errv6, dnsclient.ErrNonExistentDomain) {
		return nil, nil, errv6
	}

	return append(ipsv4, ipsv6...), append(ttlsv4, ttlsv6...), multierr.Combine(errv4, errv6)
}

func minTTL(ttls []time.Duration) time.Duration {
	min := ttls[0]
	for _, ttl := range ttls {
		if ttl < min {
			min = ttl
		}
	}
	return min
}
