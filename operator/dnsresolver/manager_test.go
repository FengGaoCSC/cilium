// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"testing"
	"time"

	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/dnsclient"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestManagerSingleFQDNGroup(t *testing.T) {
	defer goleak.VerifyNone(t)

	// mock dns server handlers
	ipv4 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		if fqdn != "cilium.io" {
			return nil, nil, fmt.Errorf("expected fqdn %q, got %q", "cilium.io", fqdn)
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, []time.Duration{time.Hour}, nil
	}
	ipv6 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::68")}, []time.Duration{time.Hour}, nil
	}

	var clientset k8sClient.Clientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		operatorK8s.ResourcesCell,
		cell.Provide(func() dnsclient.Resolver {
			return &mockClient{ipv4, ipv6}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset) error {
			clientset = c

			fqdnGroup := &v1alpha1.IsovalentFQDNGroup{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "isovalent.com/v1alpha1",
					Kind:       "IsovalentFQDNGroup",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-group",
					UID:  "test-group-uid",
				},
				Spec: v1alpha1.IsovalentFQDNGroupSpec{
					FQDNs: []v1alpha1.FQDN{"cilium.io"},
				},
			}
			if _, err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Create(
				context.Background(),
				fqdnGroup,
				metav1.CreateOptions{},
			); err != nil {
				return fmt.Errorf("failed to create IsovalentFQDNGroup %v: %w", fqdnGroup, err)
			}

			return nil
		}),

		Cell,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if err := retry(
		func() error {
			cidrGroup, err := clientset.CiliumV2alpha1().CiliumCIDRGroups().Get(
				context.Background(),
				"test-group",
				metav1.GetOptions{},
			)
			if err != nil {
				return err
			}

			ownerRefsExpected := []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IFGKindDefinition,
					Name:       "test-group",
					UID:        "test-group-uid",
				},
			}
			if !reflect.DeepEqual(cidrGroup.OwnerReferences, ownerRefsExpected) {
				return fmt.Errorf("expected owner references to be %v, got %v", ownerRefsExpected, cidrGroup.OwnerReferences)
			}

			cidrsExpected := []api.CIDR{"1.1.1.1/32", "2001:db8::68/128"}
			if !assert.ElementsMatch(t, cidrsExpected, cidrGroup.Spec.ExternalCIDRs) {
				return fmt.Errorf("expected cidrs to be %v, got %v", cidrsExpected, cidrGroup.Spec.ExternalCIDRs)
			}

			return nil
		},
	); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	if err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Delete(
		context.Background(),
		"test-group",
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatal(err)
	}

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestManagerSingleFQDNGroupSameCIDRs(t *testing.T) {
	defer goleak.VerifyNone(t)

	// mock dns server handlers
	ipv4 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		switch fqdn {
		case "cilium.io":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, []time.Duration{time.Second}, nil
		case "ebpf.io":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, []time.Duration{time.Second}, nil
		}
		return nil, nil, fmt.Errorf("unexpected fqdn %q", fqdn)
	}
	ipv6 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return nil, nil, nil
	}

	var clientset k8sClient.Clientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		operatorK8s.ResourcesCell,
		cell.Provide(func() dnsclient.Resolver {
			return &mockClient{ipv4, ipv6}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset) error {
			clientset = c

			fqdnGroups := []*v1alpha1.IsovalentFQDNGroup{
				{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "isovalent.com/v1alpha1",
						Kind:       "IsovalentFQDNGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group",
						UID:  "test-group-uid",
					},
					Spec: v1alpha1.IsovalentFQDNGroupSpec{
						FQDNs: []v1alpha1.FQDN{
							"cilium.io",
							"ebpf.io",
						},
					},
				},
			}
			for _, fqdnGroup := range fqdnGroups {
				if _, err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Create(
					context.Background(),
					fqdnGroup,
					metav1.CreateOptions{},
				); err != nil {
					return fmt.Errorf("failed to create IsovalentFQDNGroup %v: %w", fqdnGroup, err)
				}
			}

			return nil
		}),

		Cell,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if err := retry(
		func() error {
			cidrGroup, err := clientset.CiliumV2alpha1().CiliumCIDRGroups().Get(
				context.Background(),
				"test-group",
				metav1.GetOptions{},
			)
			if err != nil {
				return err
			}

			ownerRefsExpected := []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IFGKindDefinition,
					Name:       "test-group",
					UID:        "test-group-uid",
				},
			}
			if !reflect.DeepEqual(cidrGroup.OwnerReferences, ownerRefsExpected) {
				return fmt.Errorf("expected owner references to be %v, got %v", ownerRefsExpected, cidrGroup.OwnerReferences)
			}

			cidrsExpected := []api.CIDR{"1.1.1.1/32"}
			if !assert.ElementsMatch(t, cidrsExpected, cidrGroup.Spec.ExternalCIDRs) {
				return fmt.Errorf("expected cidrs to be %v, got %v", cidrsExpected, cidrGroup.Spec.ExternalCIDRs)
			}

			return nil
		},
	); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	if err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Delete(
		context.Background(),
		"test-group",
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatal(err)
	}

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestManagerMultipleSets(t *testing.T) {
	defer goleak.VerifyNone(t)

	// mock dns server handlers
	ipv4 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		switch fqdn {
		case "cilium.io":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, []time.Duration{time.Second}, nil
		case "ebpf.io":
			return []netip.Addr{netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3")}, []time.Duration{time.Second}, nil
		case "isovalent.com":
			return []netip.Addr{netip.MustParseAddr("4.4.4.4")}, []time.Duration{time.Second}, nil
		}
		return nil, nil, fmt.Errorf("unexpected fqdn %q", fqdn)
	}
	ipv6 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return nil, nil, nil
	}

	var cs k8sClient.Clientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		operatorK8s.ResourcesCell,
		cell.Provide(func() dnsclient.Resolver {
			return &mockClient{ipv4, ipv6}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset) error {
			cs = c

			fqdnGroups := []*v1alpha1.IsovalentFQDNGroup{
				{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "isovalent.com/v1alpha1",
						Kind:       "IsovalentFQDNGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-1",
					},
					Spec: v1alpha1.IsovalentFQDNGroupSpec{
						FQDNs: []v1alpha1.FQDN{
							"cilium.io",
						},
					},
				},
				{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "isovalent.com/v1alpha1",
						Kind:       "IsovalentFQDNGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-2",
					},
					Spec: v1alpha1.IsovalentFQDNGroupSpec{
						FQDNs: []v1alpha1.FQDN{
							"ebpf.io",
						},
					},
				},
			}
			for _, fqdnGroup := range fqdnGroups {
				if _, err := cs.IsovalentV1alpha1().IsovalentFQDNGroups().Create(
					context.Background(),
					fqdnGroup,
					metav1.CreateOptions{},
				); err != nil {
					return fmt.Errorf("failed to create IsovalentFQDNGroup %v: %w", fqdnGroup, err)
				}
			}

			return nil
		}),

		Cell,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	// initial status
	if err := testCIDRGroup(cs, "test-group-1", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-2", []api.CIDR{"2.2.2.2/32", "3.3.3.3/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// add a new FQDNGroup
	if err := createFQDNGroup(cs, "test-group-3", []v1alpha1.FQDN{"isovalent.com"}); err != nil {
		t.Fatal(err)
	}

	if err := testCIDRGroup(cs, "test-group-1", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-2", []api.CIDR{"2.2.2.2/32", "3.3.3.3/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-3", []api.CIDR{"4.4.4.4/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// update FQDNGroup 3 with same fqdn in group 1
	if err := updateFQDNGroup(cs, "test-group-3", []v1alpha1.FQDN{"cilium.io"}); err != nil {
		t.Fatal(err)
	}

	if err := testCIDRGroup(cs, "test-group-1", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-2", []api.CIDR{"2.2.2.2/32", "3.3.3.3/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-3", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// update FQDNGroup 2 with multiple fqdns, some of which overlap with those of the other groups
	if err := updateFQDNGroup(cs, "test-group-2", []v1alpha1.FQDN{"ebpf.io", "cilium.io", "isovalent.com"}); err != nil {
		t.Fatal(err)
	}

	if err := testCIDRGroup(cs, "test-group-1", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-2", []api.CIDR{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(cs, "test-group-3", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	// delete all FQDNGroups
	if err := deleteFQDNGroup(cs, "test-group-1"); err != nil {
		t.Fatal(err)
	}
	if err := deleteFQDNGroup(cs, "test-group-2"); err != nil {
		t.Fatal(err)
	}
	if err := deleteFQDNGroup(cs, "test-group-3"); err != nil {
		t.Fatal(err)
	}

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestManagerPeriodicResolver(t *testing.T) {
	defer goleak.VerifyNone(t)

	// mock dns server handlers
	nQueries := 0
	ipv4 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		if fqdn != "cilium.io" {
			return nil, nil, fmt.Errorf("expected fqdn %q, got %q", "cilium.io", fqdn)
		}

		var (
			ips  []netip.Addr
			ttls []time.Duration
		)
		switch nQueries {
		case 0:
			ips = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
			ttls = []time.Duration{250 * time.Millisecond}
		case 1:
			ips = []netip.Addr{netip.MustParseAddr("2.2.2.2")}
			ttls = []time.Duration{250 * time.Millisecond}
		case 2:
			ips = []netip.Addr{netip.MustParseAddr("3.3.3.3")}
			ttls = []time.Duration{250 * time.Millisecond}
		default:
			ips = []netip.Addr{netip.MustParseAddr("255.255.255.255")}
			ttls = []time.Duration{time.Hour}
		}
		nQueries++
		return ips, ttls, nil
	}
	ipv6 := func(_ context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
		return nil, nil, nil
	}

	var clientset k8sClient.Clientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		operatorK8s.ResourcesCell,
		cell.Provide(func() dnsclient.Resolver {
			return &mockClient{ipv4, ipv6}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset) error {
			clientset = c

			fqdnGroup := &v1alpha1.IsovalentFQDNGroup{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "isovalent.com/v1alpha1",
					Kind:       "IsovalentFQDNGroup",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-group",
				},
				Spec: v1alpha1.IsovalentFQDNGroupSpec{
					FQDNs: []v1alpha1.FQDN{"cilium.io"},
				},
			}
			if _, err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Create(
				context.Background(),
				fqdnGroup,
				metav1.CreateOptions{},
			); err != nil {
				return fmt.Errorf("failed to create IsovalentFQDNGroup %v: %w", fqdnGroup, err)
			}

			return nil
		}),

		cell.Provide(func() Config {
			return Config{
				FQDNGroupMinQueryInterval: time.Millisecond,
			}
		}),
		cell.Invoke(newManager),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if err := testCIDRGroup(clientset, "test-group", []api.CIDR{"1.1.1.1/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(clientset, "test-group", []api.CIDR{"2.2.2.2/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}
	if err := testCIDRGroup(clientset, "test-group", []api.CIDR{"3.3.3.3/32"}); err != nil {
		t.Fatalf("cidr group reconciliation failed: %s", err)
	}

	if err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Delete(
		context.Background(),
		"test-group",
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatal(err)
	}

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func testCIDRGroup(clientset k8sClient.Clientset, cidrGroup string, cidrs []api.CIDR) error {
	return retry(
		func() error {
			cidrGroup, err := clientset.CiliumV2alpha1().CiliumCIDRGroups().Get(
				context.Background(),
				cidrGroup,
				metav1.GetOptions{},
			)
			if err != nil {
				return err
			}
			sorted := make([]api.CIDR, len(cidrGroup.Spec.ExternalCIDRs))
			copy(sorted, cidrGroup.Spec.ExternalCIDRs)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i] < sorted[j]
			})
			if !reflect.DeepEqual(sorted, cidrs) {
				return fmt.Errorf("expected cidrs to be %v, got %v", cidrs, sorted)
			}
			return nil
		},
	)
}

func createFQDNGroup(clientset k8sClient.Clientset, name string, fqdns []v1alpha1.FQDN) error {
	fqdnGroup := &v1alpha1.IsovalentFQDNGroup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "isovalent.com/v1alpha1",
			Kind:       "IsovalentFQDNGroup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IsovalentFQDNGroupSpec{
			FQDNs: fqdns,
		},
	}
	_, err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Create(
		context.Background(),
		fqdnGroup,
		metav1.CreateOptions{},
	)
	return err
}

func updateFQDNGroup(clientset k8sClient.Clientset, name string, fqdns []v1alpha1.FQDN) error {
	fqdnGroup := &v1alpha1.IsovalentFQDNGroup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "isovalent.com/v1alpha1",
			Kind:       "IsovalentFQDNGroup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IsovalentFQDNGroupSpec{
			FQDNs: fqdns,
		},
	}
	_, err := clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Update(
		context.Background(),
		fqdnGroup,
		metav1.UpdateOptions{},
	)
	return err
}

func deleteFQDNGroup(clientset k8sClient.Clientset, name string) error {
	return clientset.IsovalentV1alpha1().IsovalentFQDNGroups().Delete(
		context.Background(),
		name,
		metav1.DeleteOptions{},
	)
}
