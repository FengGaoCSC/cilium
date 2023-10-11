//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package deploy

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/k8s"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

const (
	PhantomServicePort = 9090
)

func PhantomServiceAddress(ipFam features.IPFamily) string {
	if ipFam == features.IPFamilyV6 {
		// The 2001:db8::/32 subnet is reserved for documentation by https://www.rfc-editor.org/rfc/rfc3849
		return "2001:db8::94"
	}

	// The 192.0.2.0/24 subnet is reserved for documentation by https://www.rfc-editor.org/rfc/rfc5737.html
	return "192.0.2.94"
}

// PhantomService deploys the phantom service associated with the echo-other-node pod,
// registers the corresponding finalizer to remove it when the test terminates, and
// waits until the service has propagated to the remote nodes.
func PhantomService(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
	var (
		ns      = ct.Params().TestNamespace
		clients = ct.Clients() // Expected: []*k8s.Client{local, remote}
	)

	if len(clients) < 2 {
		return fmt.Errorf("unable to retrieve client for remote cluster")
	}

	remote := clients[1]
	svc := newPhantomService()

	t.Debugf("Deploying %q service to namespace %q...", svc.GetName(), ns)
	svc, err := remote.Clientset.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create service %q: %w", svc.Name, err)
	}

	// Register a finalizer to remove the service when the test terminates
	t.WithFinalizer(func() error {
		t.Debugf("Removing %q service from namespace %q...", svc.GetName(), ns)

		// Use a separate context so that the service gets deleted also if the test is aborted
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := remote.Clientset.CoreV1().Services(ns).Delete(fctx, svc.GetName(), metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("unable to delete service %q: %w", svc.Name, err)
		}
		return nil
	})

	// Manually configure "fake" LoadBalancer IP addresses. Additionally,
	// create a copy of the service with the "fake" IP addresses as ClusterIPs,
	// which will be used to wait for the propagation of the information.
	dummy := svc.DeepCopy()
	dummy.Spec.ClusterIPs = nil

	for _, family := range ct.Features.IPFamilies() {
		address := PhantomServiceAddress(family)
		dummy.Spec.ClusterIPs = append(dummy.Spec.ClusterIPs, address)
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress,
			corev1.LoadBalancerIngress{IP: address})
	}

	_, err = remote.Clientset.CoreV1().Services(ns).UpdateStatus(ctx, svc, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unable to update service %q: %w", svc.Name, err)
	}

	// Wait until the phantom service is propagated to the cilium agents
	// running on the nodes hosting the client pods.
	nodes := make(map[string]struct{})
	for _, client := range ct.ClientPods() {
		nodes[client.NodeName()] = struct{}{}
	}

	for _, pod := range ct.CiliumPods() {
		if _, ok := nodes[pod.NodeName()]; ok {
			t.Debugf("Waiting for service %q to propagate to node %q...", svc.GetName(), pod.NodeName())
			if err := check.WaitForServiceEndpoints(ctx, t, pod, check.Service{Service: dummy}, 1, ct.Features.IPFamilies()); err != nil {
				return fmt.Errorf("failed waiting for service %q to propagate to node %s: %w", svc.GetName(), pod.NodeName(), err)
			}
		}
	}

	return nil
}

func newPhantomService() *corev1.Service {
	ipFamPol := corev1.IPFamilyPolicyPreferDualStack
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "echo-other-node-phantom",
			Annotations: map[string]string{k8s.PhantomServiceKey: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{Name: "http-8080", Port: int32(PhantomServicePort), TargetPort: intstr.FromString("http-8080")},
			},
			Selector:       map[string]string{"name": "echo-other-node"},
			IPFamilyPolicy: &ipFamPol,

			// Prevent real LoadBalancer implementations from reconciling this service.
			LoadBalancerClass: pointer.String("isovalent.com/none"),
		},
	}
}
