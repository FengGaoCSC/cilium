// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/policy/api"
)

type testNotifier struct {
	stream   chan struct{}
	eventsFn func(stream chan struct{}) (streamID, <-chan struct{})
	stopFn   func(stream chan struct{}, sID streamID) error
	getFn    func(fqdns ...string) []netip.Prefix
}

func (n *testNotifier) events() (streamID, <-chan struct{}) {
	return n.eventsFn(n.stream)
}
func (n *testNotifier) stop(sID streamID) error {
	return n.stopFn(n.stream, sID)
}
func (n *testNotifier) get(fqdns ...string) []netip.Prefix {
	return n.getFn(fqdns...)
}

func TestReconciler(t *testing.T) {
	defer goleak.VerifyNone(t)

	// create a test logger
	logger, _ := test.NewNullLogger()

	// create fake clientsets
	cs, _ := k8sClient.NewFakeClientset()
	clientset := cs.CiliumV2alpha1().CiliumCIDRGroups()

	first, last := make(chan struct{}), make(chan struct{})

	// create a mock emitter
	n := 0
	notifier := &testNotifier{
		stream: make(chan struct{}),
		eventsFn: func(stream chan struct{}) (streamID, <-chan struct{}) {
			go func() {
				stream <- struct{}{}

				// wait for reconciliation after first notification
				<-first

				stream <- struct{}{}

				// wait for reconciliation after last notification
				<-last
			}()
			return 0, stream
		},
		stopFn: func(stream chan struct{}, sID streamID) error {
			if sID != 0 {
				return fmt.Errorf("unexpected stream id %d", sID)
			}
			close(stream)
			return nil
		},
		getFn: func(fqdns ...string) []netip.Prefix {
			n++
			switch n {
			case 1:
				return []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}
			case 2:
				return []netip.Prefix{
					netip.MustParsePrefix("2.2.2.2/32"),
					netip.MustParsePrefix("3.3.3.3/32"),
					netip.MustParsePrefix("4.4.4.4/32"),
				}
			}
			return nil
		},
	}

	mgrCtr := controller.NewManager()

	reconciler := newReconciler(
		logger,
		"test-fqdn-group",
		"test-fqdn-group-uid",
		[]string{"cilium.io", "ebpf.io", "isovalent.com"},
		clientset,
		mgrCtr,
		notifier,
	)

	if err := reconciler.run(); err != nil {
		t.Fatalf("reconciler run failed: %s", err)
	}

	if err := retry(
		func() error {
			cidrGroup, err := clientset.Get(
				context.Background(),
				"test-fqdn-group",
				metav1.GetOptions{},
			)
			if err != nil {
				return err
			}
			expected := []api.CIDR{"1.1.1.1/32"}
			if !reflect.DeepEqual(cidrGroup.Spec.ExternalCIDRs, expected) {
				return fmt.Errorf("expected cidrs to be %v, got %v", expected, cidrGroup.Spec.ExternalCIDRs)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// signal that the first notification has been received
	close(first)

	if err := retry(
		func() error {
			cidrGroup, err := clientset.Get(
				context.Background(),
				"test-fqdn-group",
				metav1.GetOptions{},
			)
			if err != nil {
				return err
			}
			expected := []api.CIDR{"2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/32"}
			if !reflect.DeepEqual(cidrGroup.Spec.ExternalCIDRs, expected) {
				return fmt.Errorf("expected cidrs to be %v, got %v", expected, cidrGroup.Spec.ExternalCIDRs)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// signal that the last notification has been received
	close(last)

	reconciler.close()

	mgrCtr.RemoveAllAndWait()
}
