//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/service/store"
)

const (
	// CEServicePrefix is the common prefix for service related annotations
	// used for enterprise-only functionalities.
	CEServicePrefix = "service.isovalent.com"

	// PhantomServiceKey if set to true, marks a service (which must be of type
	// LoadBalancer) to become a phantom service. It means that the corresponding
	// LB IP address becomes reachable from the remote clusters, even if a service
	// with the same namespace/name does not exist there.
	PhantomServiceKey = CEServicePrefix + "/phantom"
)

// PhantomServiceMutator mutates the svcInfo in order to make the service
// reachable in remote clusters, if it is marked to be of type phantom.
func PhantomServiceMutator(svc *slim_corev1.Service, svcInfo *Service) {
	if !getAnnotationPhantom(svc) {
		return
	}

	svcInfo.IncludeExternal = false
	svcInfo.Shared = true

	// In case of phantom services, we configure the LoadBalancerIPs to be the
	// service frontends, since they must be unique across clusters
	// (this does not hold true for ClusterIPs in case ServiceCIDRs overlap).
	svcInfo.FrontendIPs = make([]net.IP, 0)
	for _, entry := range svc.Status.LoadBalancer.Ingress {
		if ip := net.ParseIP(entry.IP); ip != nil {
			svcInfo.FrontendIPs = append(svcInfo.FrontendIPs, ip)
		}
	}
}

func getAnnotationPhantom(svc *slim_corev1.Service) bool {
	// Cannot be a phantom service if it's already declared as global, or it is not of type LB.
	if getAnnotationIncludeExternal(svc) || svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return false
	}

	if value, ok := annotation.Get(svc, PhantomServiceKey); ok {
		return strings.ToLower(value) == "true"
	}

	return false
}

func isPhantomService(s *store.ClusterService) bool {
	return !s.IncludeExternal && s.Shared
}
