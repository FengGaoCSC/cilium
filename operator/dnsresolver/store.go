// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"errors"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// streamID identifies the ID of a subscription to the
// mapping events produced from an emitter.
type streamID uint

// errSubscriberNotFound is returned by stop when the subscriber ID cannot be found.
var errSubscriberNotFound = errors.New("unable to find subscriber id")

type notifier interface {
	// events subscribes to the fqdn related events of the emitter.
	// It returns a streamID to identify the subscription and a channel
	// to listen for the events.
	events() (streamID, <-chan struct{})

	// stop unsubscribes from the stream identified by the streamID.
	stop(sID streamID) error

	// get returns the current status of the prefixes mapping for a list
	// of fqdns. The returned list of prefixes is deduplicated.
	get(fqdns ...string) []netip.Prefix
}

type store interface {
	// set updates the store with the mapping fqdn -> prefixes
	set(fqdn string, prefixes []netip.Prefix)
}

type fqdnMappings struct {
	lock.Mutex
	m map[string][]netip.Prefix
}

type storeSubscribers struct {
	lock.Mutex

	s map[streamID]chan struct{}

	// subscription ID to use for the next store subscriber
	nextID streamID
}

// fqdnStore is a store specialized for fqdn -> prefixes mapping.
// It supports subscriptions to notify consumers when its internal status
// has been updated.
type fqdnStore struct {
	mappings fqdnMappings

	subscribers storeSubscribers
}

func newStore() *fqdnStore {
	return &fqdnStore{
		mappings: fqdnMappings{
			m: make(map[string][]netip.Prefix),
		},
		subscribers: storeSubscribers{
			s: make(map[streamID]chan struct{}),
		},
	}
}

func (s *fqdnStore) events() (streamID, <-chan struct{}) {
	s.subscribers.Lock()
	defer s.subscribers.Unlock()

	// we use a buffered channel to avoid blocking if the consumer
	// is not ready to handle the notification immediately
	events := make(chan struct{}, 1)
	events <- struct{}{}

	// find first available id
	for _, ok := s.subscribers.s[s.subscribers.nextID]; ok; {
		s.subscribers.nextID++
	}
	s.subscribers.s[s.subscribers.nextID] = events
	subID := s.subscribers.nextID
	s.subscribers.nextID++

	return subID, events
}

func (s *fqdnStore) stop(sID streamID) error {
	s.subscribers.Lock()
	defer s.subscribers.Unlock()

	if _, ok := s.subscribers.s[sID]; !ok {
		return errSubscriberNotFound
	}

	close(s.subscribers.s[sID])
	delete(s.subscribers.s, sID)

	return nil
}

func (s *fqdnStore) get(fqdns ...string) []netip.Prefix {
	s.mappings.Lock()
	defer s.mappings.Unlock()

	var prefixes []netip.Prefix
	for _, fqdn := range fqdns {
		prefs, ok := s.mappings.m[fqdn]
		if !ok {
			continue
		}
		prefixes = append(prefixes, prefs...)
	}
	prefixes = dedup(prefixes)

	return prefixes
}

func (s *fqdnStore) set(fqdn string, prefixes []netip.Prefix) {
	s.mappings.Lock()
	s.mappings.m[fqdn] = prefixes
	s.mappings.Unlock()

	s.notifyAll()
}

func (s *fqdnStore) notifyAll() {
	s.subscribers.Lock()
	defer s.subscribers.Unlock()

	for _, ch := range s.subscribers.s {
		// if the channel is full, a previous notification
		// has not yet been consumed but will eventually be,
		// so no need to do anything. Also, we should avoid
		// blocking to allow other consumers to manage notifications
		// as soon as possible.
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func dedup[T comparable](s []T) []T {
	if len(s) == 0 {
		return s
	}
	set := make(map[T]struct{})
	for _, v := range s {
		set[v] = struct{}{}
	}
	uniq := make([]T, 0, len(set))
	for v := range set {
		uniq = append(uniq, v)
	}
	return uniq
}
