// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cache

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/golang/protobuf/ptypes"
)

func (c *Cache) aggregateFlow(a *types.AggregatedFlow, f types.AggregatableFlow) (r *types.Result) {
	r = &types.Result{}
	var s *observer.DirectionStatistics

	if a.Stats.Reply == nil {
		a.Stats.Reply = &observer.DirectionStatistics{}
	}

	if a.Stats.Forward == nil {
		a.Stats.Forward = &observer.DirectionStatistics{}
	}

	if f.IsReply() {
		s = a.Stats.Reply
		if s.NumFlows == 0 {
			// This is the first flow observed with is_reply set to true.
			// Set the first_reply state change.
			r.StateChange |= observer.StateChange_first_reply
		}
	} else {
		s = a.Stats.Forward
	}

	s.LastActivity = ptypes.TimestampNow()
	s.NumFlows++

	if f.State().ACK {
		s.AckSeen = true
	}

	state := f.State()
	switch {
	case state.Error:
		if s.Errors == 0 {
			r.StateChange |= observer.StateChange_first_error
		} else {
			r.StateChange |= observer.StateChange_error
		}
		s.Errors++
	case state.CloseRequest:
		s.CloseRequests++
	case state.ConnectionRequest:
		s.ConnectionAttempts++
	}

	if c.conf.AggregateFunc != nil {
		c.conf.AggregateFunc(a, s, f, r)
	}

	if s.FirstActivity.GetSeconds() == 0 && s.FirstActivity.GetNanos() == 0 {
		s.FirstActivity = s.LastActivity
	}

	r.AggregatedFlow = a
	r.Reply = true
	return
}

// Cache is an aggregation cache used to store historic flows for
// identification of aggregation potential
type Cache struct {
	conf Configuration

	// mutex protects the cache
	mutex sync.Mutex
	cache map[types.Hash][]*types.AggregatedFlow
	// shutdown channel is used to communicate that the GC goroutine stopped.
	shutdown chan struct{}
}

// Configuration is the configuration of an aggregation cache
type Configuration struct {
	CompareFunc   types.FlowCompareFunc
	HashFunc      types.FlowHashFunc
	AggregateFunc func(a *types.AggregatedFlow, s *observer.DirectionStatistics, f types.AggregatableFlow, r *types.Result)
	Expiration    time.Duration
	// Disables the goroutine that periodically evicts expired entries from the cache.
	// For testing only.
	DisableGC bool
	RenewTTL  bool
}

// NewCache returns a new aggregation cache
func NewCache(ctx context.Context, conf Configuration) *Cache {
	if conf.Expiration == time.Duration(0) {
		conf.Expiration = time.Minute
	}

	c := &Cache{
		conf:     conf,
		cache:    map[types.Hash][]*types.AggregatedFlow{},
		shutdown: make(chan struct{}, 1),
	}

	if conf.DisableGC {
		return c
	}

	go func() {
		tick := time.NewTicker(c.conf.Expiration).C
		for {
			select {
			case <-tick:
				c.mutex.Lock()
				now := time.Now()
				for k, v := range c.cache {
					var valid []*types.AggregatedFlow
					for _, c := range v {
						if c.Expires.After(now) {
							valid = append(valid, c)
						}
					}
					if len(valid) > 0 {
						c.cache[k] = valid
					} else {
						delete(c.cache, k)
					}
				}
				c.mutex.Unlock()
			case <-ctx.Done():
				c.shutdown <- struct{}{}
				return
			}
		}
	}()

	return c
}

// Aggregate performs aggregation of a flow based on the existing cache content
func (c *Cache) Aggregate(f types.AggregatableFlow) *types.Result {
	var isNew bool

	expires := time.Now().Add(c.conf.Expiration)
	hash := c.conf.HashFunc(f)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	a := c.lookup(hash, f)
	if a == nil {
		if c.cache[hash] == nil {
			c.cache[hash] = []*types.AggregatedFlow{}
		}

		a = &types.AggregatedFlow{Expires: expires, FirstFlow: f}
		c.cache[hash] = append(c.cache[hash], a)
		isNew = true
	}

	if c.conf.RenewTTL {
		a.Expires = expires
	}
	result := c.aggregateFlow(a, f)
	if isNew {
		result.StateChange |= observer.StateChange_new
	}

	return result
}

// Lookup returns the aggregated flow if the flow passed into the Lookup
// function can be found in the cache
func (c *Cache) Lookup(f types.AggregatableFlow) *types.AggregatedFlow {
	hash := c.conf.HashFunc(f)
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.lookup(hash, f)
}

func (c *Cache) lookup(hash types.Hash, f types.AggregatableFlow) *types.AggregatedFlow {
	now := time.Now()

	if chain, ok := c.cache[hash]; ok {
		// Iterate over the chain backward. The order is important here in case the list
		// contains an expired flow that hasn't been evicted by the background goroutine.
		// The Aggregate function appends a new entry at the end of the list if there is
		// an expired flow in the list. If this function iterates over the list from the
		// beginning of the list, this function ends up marking all the subsequent flows
		// as new until the background goroutine evicts the expired flow. This is because
		// the lookup function returns nil as soon as it finds a matching flow that has
		// expired.
		for i := len(chain) - 1; i >= 0; i-- {
			if c.conf.CompareFunc(chain[i].FirstFlow, f) {
				if chain[i].Expires.Before(now) {
					return nil
				}

				return chain[i]
			}
		}
	}

	return nil
}

// WaitForShutdown blocks until either the context is cancelled or the GC goroutine
// shuts down.
func (c *Cache) WaitForShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdown:
		return nil
	}
}
