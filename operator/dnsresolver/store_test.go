// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestStoreSet(t *testing.T) {
	testCases := [...]struct {
		name   string
		apply  func(*fqdnStore)
		fqdns  []string
		status []netip.Prefix
	}{
		{
			name:   "empty",
			apply:  func(store *fqdnStore) {},
			fqdns:  nil,
			status: nil,
		},
		{
			name: "empty fqdn",
			apply: func(store *fqdnStore) {
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
			},
			fqdns:  []string{"ebpf.io"},
			status: nil,
		},
		{
			name: "multiple fqdns get all",
			apply: func(store *fqdnStore) {
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
				store.set("ebpf.io", []netip.Prefix{
					netip.MustParsePrefix("2.2.2.2/32"),
					netip.MustParsePrefix("1.1.1.1/32"),
				})
				store.set("isovalent.com", []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")})
			},
			fqdns: []string{"cilium.io", "ebpf.io", "isovalent.com"},
			status: []netip.Prefix{
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("2.2.2.2/32"),
				netip.MustParsePrefix("3.3.3.3/32"),
				netip.MustParsePrefix("4.4.4.4/32"),
			},
		},
		{
			name: "multiple fqdns get single",
			apply: func(store *fqdnStore) {
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
				store.set("ebpf.io", []netip.Prefix{
					netip.MustParsePrefix("2.2.2.2/32"),
					netip.MustParsePrefix("1.1.1.1/32"),
				})
				store.set("isovalent.com", []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")})
			},
			fqdns: []string{"ebpf.io"},
			status: []netip.Prefix{
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("2.2.2.2/32"),
			},
		},
		{
			name: "overwrite fqdn",
			apply: func(store *fqdnStore) {
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
				store.set("cilium.io", []netip.Prefix{
					netip.MustParsePrefix("2.2.2.2/32"),
					netip.MustParsePrefix("1.1.1.1/32"),
				})
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")})
			},
			fqdns:  []string{"cilium.io"},
			status: []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")},
		},
		{
			name: "dedup fqdns",
			apply: func(store *fqdnStore) {
				store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
				store.set("ebpf.io", []netip.Prefix{
					netip.MustParsePrefix("3.3.3.3/32"),
					netip.MustParsePrefix("1.1.1.1/32"),
				})
			},
			fqdns: []string{"cilium.io", "ebpf.io"},
			status: []netip.Prefix{
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("3.3.3.3/32"),
			},
		},
	}

	for _, tc := range testCases {
		defer goleak.VerifyNone(t)

		store := newStore()

		tc.apply(store)
		prefixes := store.get(tc.fqdns...)

		assert.ElementsMatch(t, tc.status, prefixes)
	}
}

func TestStoreConcurrentSet(t *testing.T) {
	defer goleak.VerifyNone(t)

	apply := [...]func(*fqdnStore){
		func(store *fqdnStore) {
			store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
			store.set("cilium.io", []netip.Prefix{
				netip.MustParsePrefix("2.2.2.2/32"),
				netip.MustParsePrefix("1.1.1.1/32"),
			})
			store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")})
		},
		func(store *fqdnStore) {
			store.set("ebpf.io", []netip.Prefix{
				netip.MustParsePrefix("5.5.5.5/32"),
				netip.MustParsePrefix("6.6.6.6/32"),
			})
			store.set("ebpf.io", []netip.Prefix{netip.MustParsePrefix("5.5.5.5/32")})
		},
		func(store *fqdnStore) {
			store.set("isovalent.com", []netip.Prefix{netip.MustParsePrefix("7.7.7.7/32")})
			store.set("isovalent.com", []netip.Prefix{
				netip.MustParsePrefix("9.9.9.9/32"),
				netip.MustParsePrefix("8.8.8.8/32"),
			})
		},
	}

	store := newStore()

	var wg sync.WaitGroup
	for i := range apply {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for i := range apply {
				apply[i](store)
			}
		}(i)
	}
	wg.Wait()

	prefixes := store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
	expected := []netip.Prefix{
		netip.MustParsePrefix("4.4.4.4/32"),
		netip.MustParsePrefix("5.5.5.5/32"),
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("9.9.9.9/32"),
	}

	assert.ElementsMatch(t, expected, prefixes)
}

func TestStoreSubscriber(t *testing.T) {
	defer goleak.VerifyNone(t)

	before := func(store *fqdnStore) {
		store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
		store.set("cilium.io", []netip.Prefix{
			netip.MustParsePrefix("2.2.2.2/32"),
			netip.MustParsePrefix("1.1.1.1/32"),
		})
		store.set("ebpf.io", []netip.Prefix{
			netip.MustParsePrefix("5.5.5.5/32"),
			netip.MustParsePrefix("6.6.6.6/32"),
		})
		store.set("isovalent.com", []netip.Prefix{netip.MustParsePrefix("7.7.7.7/32")})
	}
	after := func(store *fqdnStore) {
		store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("4.4.4.4/32")})
		store.set("ebpf.io", []netip.Prefix{netip.MustParsePrefix("5.5.5.5/32")})
		store.set("isovalent.com", []netip.Prefix{
			netip.MustParsePrefix("9.9.9.9/32"),
			netip.MustParsePrefix("8.8.8.8/32"),
		})
	}

	store := newStore()

	subscribed := make(chan struct{})
	unsubscribed := make(chan struct{})
	sent := make(chan struct{})

	// run the subscriber
	errs := make(chan error)
	go func() {
		defer close(errs)

		prefixes := store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		if prefixes != nil {
			errs <- fmt.Errorf("expected prefixes to be nil, got %v", prefixes)
		}

		id, stream := store.events()

		received := make(chan struct{})
		go func() {
			// wait for all events to be received
			<-received

			// unsubscribe
			store.stop(id)

			// signal that the subscriber canceled the subscription
			close(unsubscribed)
		}()

		// signal that the subscriber is ready to receive events
		close(subscribed)

		// we should receive at least one notification
		<-stream

		// wait for all store operations to take place
		<-sent

		prefixes = store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		expected := []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
			netip.MustParsePrefix("2.2.2.2/32"),
			netip.MustParsePrefix("5.5.5.5/32"),
			netip.MustParsePrefix("6.6.6.6/32"),
			netip.MustParsePrefix("7.7.7.7/32"),
		}
		if !assert.ElementsMatch(t, expected, prefixes) {
			errs <- fmt.Errorf("expected prefixes to be %v, got %v", expected, prefixes)
		}

		// signal that the subscriber received the events
		close(received)
	}()

	// run the store in a separate goroutine, so the main one will listen for errors from subscriber
	stop := make(chan struct{})
	go func() {
		// wait for the subscriber to be ready before notifying events
		<-subscribed

		before(store)

		// signal that all the store operations have been completed
		close(sent)

		// wait for the subscriber to close subscription
		<-unsubscribed

		// subsequent set operations should not block the store
		after(store)

		// signal that the store is closed
		close(stop)
	}()

	// check for errors from subscriber
	for err := range errs {
		t.Fatal(err)
	}

	// wait for the store to be closed
	<-stop
}

func TestStoreConcurrentSubscribers(t *testing.T) {
	defer goleak.VerifyNone(t)

	apply := func(store *fqdnStore) {
		store.set("cilium.io", []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")})
		store.set("cilium.io", []netip.Prefix{
			netip.MustParsePrefix("2.2.2.2/32"),
			netip.MustParsePrefix("1.1.1.1/32"),
		})
		store.set("ebpf.io", []netip.Prefix{
			netip.MustParsePrefix("5.5.5.5/32"),
			netip.MustParsePrefix("6.6.6.6/32"),
		})
		store.set("isovalent.com", []netip.Prefix{netip.MustParsePrefix("7.7.7.7/32")})
	}

	store := newStore()

	var subA, subB streamID
	subscribedA, subscribedB := make(chan struct{}), make(chan struct{})
	sent := make(chan struct{})

	// run subscriber A
	errsA := make(chan error)
	go func() {
		defer close(errsA)

		prefixes := store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		if prefixes != nil {
			errsA <- fmt.Errorf("subscriber A expected prefixes to be nil, got %v", prefixes)
		}

		var stream <-chan struct{}
		subA, stream = store.events()

		// signal that the subscriber is ready to receive events
		close(subscribedA)

		// we should receive at least one notification
		<-stream

		// wait for all store operations to take place
		<-sent

		prefixes = store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		expected := []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
			netip.MustParsePrefix("2.2.2.2/32"),
			netip.MustParsePrefix("5.5.5.5/32"),
			netip.MustParsePrefix("6.6.6.6/32"),
			netip.MustParsePrefix("7.7.7.7/32"),
		}
		if !assert.ElementsMatch(t, expected, prefixes) {
			errsA <- fmt.Errorf("subscriber A expected prefixes to be %v, got %v", expected, prefixes)
		}
	}()

	// run subscriber B
	errsB := make(chan error)
	go func() {
		defer close(errsB)

		prefixes := store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		if prefixes != nil {
			errsB <- fmt.Errorf("subscriber B expected prefixes to be nil, got %v", prefixes)
		}

		var stream <-chan struct{}
		subB, stream = store.events()

		// signal that the subscriber is ready to receive events
		close(subscribedB)

		// we should receive at least one notification
		<-stream

		// wait for all store operations to take place
		<-sent

		prefixes = store.get([]string{"cilium.io", "ebpf.io", "isovalent.com"}...)
		expected := []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
			netip.MustParsePrefix("2.2.2.2/32"),
			netip.MustParsePrefix("5.5.5.5/32"),
			netip.MustParsePrefix("6.6.6.6/32"),
			netip.MustParsePrefix("7.7.7.7/32"),
		}
		if !assert.ElementsMatch(t, expected, prefixes) {
			errsB <- fmt.Errorf("subscriber B expected prefixes to be %v, got %v", expected, prefixes)
		}
	}()

	// run the store in a separate goroutine, so the main one will listen for errors from subscribers
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// wait for subscribers to be ready before notifying events
		<-subscribedA
		<-subscribedB

		apply(store)

		// signal that all the store operations have been completed
		close(sent)

		// remove subscriptions
		store.stop(subA)
		store.stop(subB)
	}()

	// check for errors from subscriber
	for err := range merge(errsA, errsB) {
		t.Fatal(err)
	}

	// wait for the store goroutine
	wg.Wait()
}

func merge[T any](chs ...<-chan T) <-chan T {
	merged := make(chan T)

	var wg sync.WaitGroup
	for _, ch := range chs {
		wg.Add(1)
		go func(ch <-chan T) {
			defer wg.Done()
			for v := range ch {
				merged <- v
			}
		}(ch)
	}

	go func() {
		wg.Wait()
		close(merged)
	}()

	return merged
}

func TestDedup(t *testing.T) {
	testcases := []struct {
		name   string
		input  []netip.Prefix
		output []netip.Prefix
	}{
		{
			name:   "empty prefixes",
			input:  []netip.Prefix{},
			output: []netip.Prefix{},
		},
		{
			name: "no duplicates",
			input: []netip.Prefix{
				netip.MustParsePrefix("3.3.3.3/32"),
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("2.2.2.2/32"),
			},
			output: []netip.Prefix{
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("2.2.2.2/32"),
				netip.MustParsePrefix("3.3.3.3/32"),
			},
		},
		{
			name: "with duplicates",
			input: []netip.Prefix{
				netip.MustParsePrefix("3.3.3.3/32"),
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("3.3.3.3/32"),
			},
			output: []netip.Prefix{
				netip.MustParsePrefix("1.1.1.1/32"),
				netip.MustParsePrefix("3.3.3.3/32"),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, dedup(tc.input), tc.output)
		})
	}
}
