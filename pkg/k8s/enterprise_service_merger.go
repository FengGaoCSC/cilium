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
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// CEServiceMerger wraps a ServiceCache, overriding the cluster service merging
// logic to support additional enterprise features (e.g., phantom services).
type CEServiceMerger struct {
	sc *ServiceCache
}

func NewCEServiceMerger(sc *ServiceCache) CEServiceMerger {
	return CEServiceMerger{
		sc: sc,
	}
}

// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
// the local service cache. The service endpoints are stored as external endpoints
// and are correlated on demand with local services via correlateEndpoints().
// It supports both standard global services and phantom services. In addition, it
// performs the appropriate operations to switch from a global to a phantom service
// (or vice versa) if necessary.
func (s CEServiceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	s.sc.mutex.Lock()
	defer s.sc.mutex.Unlock()

	s.mergeServiceUpdateLocked(service, swg)
}

// MergeExternalServiceDelete merges the deletion of a cluster service in a
// remote cluster into the local service cache. The service endpoints are
// stored as external endpoints and are correlated on demand with local
// services via correlateEndpoints().
func (s CEServiceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	s.sc.MergeExternalServiceDelete(service, swg)
}

// mergeServiceUpdateLocked processes a cluster service update, supporting both
// standard global services and phantom services. In addition, it performs the
// appropriate operations to switch from a global to a phantom service (or vice
// versa) if necessary.
//
// Must be called while holding s.mutex for writing.
func (s *CEServiceMerger) mergeServiceUpdateLocked(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	// With phantom services, we'll import the phantom service into ServiceCache.
	// Phantom services must be identified with Cluster + Name + Namespace.
	// Otherwise, naming collision is possible if they exist in multiple clusters.
	globalID := ServiceID{Cluster: service.Cluster, Name: service.Name, Namespace: service.Namespace}
	localID := ServiceID{Name: service.Name, Namespace: service.Namespace}

	svc, globalOk := s.sc.services[globalID]
	if isPhantomService(service) {
		var oldService *Service
		if !globalOk || !svc.EqualsClusterService(service) {
			log.WithField(logfields.ServiceName, service.String()).Debug("Added new phantom service")

			// Import/update the phantom service into the Service cache, so that
			// it can then be pushed into datapath.
			oldService = svc
			svc = ParseClusterService(service)
			s.sc.services[globalID] = svc

			if !globalOk {
				// Check if a global service with the same namespace/name exists in the local cluster,
				// and in that case trigger an update also for that, to ensure that leftover endpoints
				// are removed when transitioning from global to phantom.
				if local, localOk := s.sc.services[localID]; localOk && local.IncludeExternal {
					s.sc.mergeExternalServiceDeleteLocked(service, swg)
				}
			}
		}

		// oldService is propagated to handle possible changes of the frontend
		// addresses (i.e., the remote LB VIP addresses in this case).
		s.sc.mergeServiceUpdateLocked(service, oldService, swg, optClusterAware)
		return
	}

	if globalOk {
		// A service previously marked as phantom is no longer so, hence it is
		// treated as if it had been deleted. If the service is also marked as
		// shared, then the backends will be merged with the local ones as usual.
		s.sc.mergeExternalServiceDeleteLocked(service, swg, optClusterAware)
	}

	s.sc.mergeServiceUpdateLocked(service, nil, swg)
}
