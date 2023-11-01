// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package multinetwork

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
)

// defaultNetwork is the default IsovalentPodNetwork resource created by the operator.
// It references the default CiliumPodIPPool, which is used as the fallback
// in multi-pool IPAM mode if no other pool is configured for a pod.
var defaultNetwork = &v1alpha1.IsovalentPodNetwork{
	ObjectMeta: metav1.ObjectMeta{
		Name: "default",
	},
	Spec: v1alpha1.PodNetworkSpec{
		IPAM: v1alpha1.IPAMSpec{
			Mode: "multi-pool",
			Pool: v1alpha1.IPAMPoolSpec{
				Name: "default",
			},
		},
	},
}

type operatorParams struct {
	cell.In

	Config config

	Logger      logrus.FieldLogger
	Lifecycle   hive.Lifecycle
	JobRegistry job.Registry

	Clientset k8sClient.Clientset
}

type Operator struct {
	config config
	logger logrus.FieldLogger

	podNetworkClient isovalent_client_v1alpha1.IsovalentPodNetworkInterface
}

// newMultiNetworkOperator creates a new operator cell for the multi-network feature.
// This cell is responsible for creating the default IsovalentPodNetwork resource
// via a one-shot job.
// Creating a default IsovalentPodNetwork is needed to run any pods that do not
// have a multi-network annotation, as such pods will be attached to the
// "default" network by default. Without a default network, such pods would
// be stuck in ContainerCreating state.
func newMultiNetworkOperator(params operatorParams) *Operator {
	if !params.Config.EnableMultiNetwork || !params.Clientset.IsEnabled() {
		return nil
	}

	jobGroup := params.JobRegistry.NewGroup(
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "multinetwork")),
	)

	operator := &Operator{
		config:           params.Config,
		logger:           params.Logger,
		podNetworkClient: params.Clientset.IsovalentV1alpha1().IsovalentPodNetworks(),
	}

	if params.Config.AutoCreateDefaultPodNetwork {
		jobGroup.Add(
			job.OneShot("create default network",
				operator.Run, job.WithRetry(3, workqueue.DefaultControllerRateLimiter())),
		)
		params.Lifecycle.Append(jobGroup)
	}

	return operator
}

// Run creates the default IsovalentPodNetwork resource.
// It is started as a one-shot job by the operator cell.
func (o *Operator) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	scopedLog := o.logger.WithField("networkName", "default")
	scopedLog.Info("Creating IsovalentPodNetwork resource")
	_, err := o.podNetworkClient.Create(ctx, defaultNetwork, metav1.CreateOptions{})
	if err != nil {
		if k8sErrors.IsAlreadyExists(err) {
			// Nothing to do, we will not try to update an existing resource
			scopedLog.Info("Found existing IsovalentPodNetwork resource. Skipping creation")
		} else {
			return fmt.Errorf("failed to create IsovalentPodNetwork resource: %w", err)
		}
	}

	return nil
}
