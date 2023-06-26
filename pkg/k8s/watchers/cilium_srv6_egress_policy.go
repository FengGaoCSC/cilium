// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/srv6"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumSRv6EgressPolicyInit(ciliumNPClient client.Clientset) {
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2alpha1().RESTClient(),
			"ciliumSRv6Egresspolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumSRv6EgressPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(metricCSREP, "CiliumSRv6EgressPolicy", resources.MetricCreate, valid, equal)
				}()
				if csrep := k8s.ObjToCSREP(obj); csrep != nil {
					valid = true
					err := k.addCiliumSRv6EgressPolicy(csrep)
					k.K8sEventProcessed(metricCSREP, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(metricCSREP, "CiliumSRv6EgressPolicy", resources.MetricUpdate, valid, equal)
				}()

				newCsrep := k8s.ObjToCSREP(newObj)
				if newCsrep == nil {
					return
				}
				valid = true
				addErr := k.addCiliumSRv6EgressPolicy(newCsrep)
				k.K8sEventProcessed(metricCSREP, resources.MetricUpdate, addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(metricCSREP, "CiliumSRv6EgressPolicy", resources.MetricDelete, valid, equal)
				}()
				csrep := k8s.ObjToCSREP(obj)
				if csrep == nil {
					return
				}
				valid = true
				k.deleteCiliumSRv6EgressPolicy(csrep)
				k.K8sEventProcessed(metricCSREP, resources.MetricDelete, true)
			},
		},
		k8s.ConvertToCiliumSRv6EgressPolicy,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumSRv6EgressPolicyV2Alpha1,
	)

	go egpController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumSRv6EgressPolicyV2Alpha1)
}

func (k *K8sWatcher) addCiliumSRv6EgressPolicy(csrep *cilium_v2alpha1.CiliumSRv6EgressPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumSRv6EgressPolicyName: csrep.ObjectMeta.Name,
		logfields.K8sUID:                     csrep.ObjectMeta.UID,
		logfields.K8sAPIVersion:              csrep.TypeMeta.APIVersion,
	})

	ep, err := srv6.ParsePolicy(csrep)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumSRv6EgressPolicy: malformed egress policy.")
		return err
	}
	k.srv6Manager.OnAddSRv6Policy(*ep)
	return nil
}

func (k *K8sWatcher) deleteCiliumSRv6EgressPolicy(csrep *cilium_v2alpha1.CiliumSRv6EgressPolicy) {
	epID := srv6.ParseEgressPolicyID(csrep)
	k.srv6Manager.OnDeleteSRv6Policy(epID)
}
