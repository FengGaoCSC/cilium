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
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	cmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

// CEServiceMerger wraps a ServiceCache, overriding the cluster service merging
// logic to support additional enterprise features (e.g., phantom services).
type CEServiceMerger struct {
	sc    *ServiceCache
	cmcfg cmcfg.Config
}

func NewCEServiceMerger(sc *ServiceCache, cmcfg cmcfg.Config) CEServiceMerger {
	return CEServiceMerger{
		sc:    sc,
		cmcfg: cmcfg,
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

	if s.cmcfg.EnableClusterAwareAddressing {
		service = annotateBackendsWithID(*service)
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

// annotateBackendsWithID annotates each backend of the service with the
// associated cluster ID, so that it can then be parsed and eventually
// propagated to the datapath for Overlapping PodCIDR support.
//
// The service object is passed by value to create a shallow copy, and
// avoid mutating the original one during this operation.
func annotateBackendsWithID(service serviceStore.ClusterService) *serviceStore.ClusterService {
	backends := make(map[string]serviceStore.PortConfiguration, len(service.Backends))

	for backend, value := range service.Backends {
		backends[cmtypes.AnnotateIPCacheKeyWithClusterID(backend, service.ClusterID)] = value
	}

	service.Backends = backends
	return &service
}
