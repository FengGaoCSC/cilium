// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
	"golang.org/x/exp/slices"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/policy/api"
)

// reconciler watches for events related to each fqdn that is
// part of its fqdngroup and reconcile the related cidr group
// object accordingly.
type reconciler struct {
	logger logrus.FieldLogger

	fqdnGroup    string
	fqdnGroupUID types.UID
	fqdns        []string

	clientset cilium_client_v2alpha1.CiliumCIDRGroupInterface
	ctrMgr    *controller.Manager

	store    notifier
	streamID streamID

	wp    *workerpool.WorkerPool
	cache []netip.Prefix
}

func newReconciler(
	logger logrus.FieldLogger,
	fqdnGroup string,
	fqdnGroupUID types.UID,
	fqdns []string,
	clientset cilium_client_v2alpha1.CiliumCIDRGroupInterface,
	ctrMgr *controller.Manager,
	store notifier,
) *reconciler {
	return &reconciler{
		logger:       logger.WithField("fromFQDNGroup", fqdnGroup),
		fqdnGroup:    fqdnGroup,
		fqdnGroupUID: fqdnGroupUID,
		fqdns:        fqdns,
		clientset:    clientset,
		ctrMgr:       ctrMgr,
		store:        store,
		wp:           workerpool.New(1),
	}
}

func (r *reconciler) run() error {
	id, stream := r.store.events()
	r.streamID = id
	return r.wp.Submit(
		"reconciler-"+r.fqdnGroup,
		func(_ context.Context) error {
			for range stream {
				prefixes := r.store.get(r.fqdns...)
				if r.cache != nil && slices.Equal(prefixes, r.cache) {
					continue
				}
				r.cache = prefixes

				cidrs := cidrs(r.cache)
				r.ctrMgr.UpdateController(
					r.fqdnGroup,
					controller.ControllerParams{
						DoFunc: func(ctx context.Context) error {
							return r.upsertCIDRGroup(ctx, cidrs)
						},
					},
				)
			}
			return nil
		},
	)
}

func (r *reconciler) close() error {
	var errs []error
	if err := r.store.stop(r.streamID); err != nil {
		if errors.Is(err, errSubscriberNotFound) {
			r.logger.WithError(err).Error(
				"Reconciler could not be stopped due to missing underlying subscriber. There's no leak, but please report this behavior to the developers. Continuing with deletion.",
			)
		} else {
			r.logger.WithError(err).Error(
				"Reconciler could not be stopped because it already was. There's no leak, but please report this behavior to the developers. Continuing with deletion.",
			)
		}
		errs = append(errs, err)
	}
	if err := r.wp.Close(); err != nil {
		errs = append(errs, err)
	}
	return multierr.Combine(errs...)
}

func cidrs(prefixes []netip.Prefix) []api.CIDR {
	cidrs := make([]api.CIDR, 0, len(prefixes))
	for _, prefix := range prefixes {
		cidrs = append(cidrs, api.CIDR(prefix.String()))
	}
	return cidrs
}

func (r *reconciler) upsertCIDRGroup(ctx context.Context, cidrs []api.CIDR) error {
	logger := r.logger.WithField("cidrs", cidrs)

	logger.Debug("reconciling cidr group")

	var cidrsPatch []byte
	cidrsPatch, err := json.Marshal(
		[]k8s.JSONPatch{
			{
				OP:    "replace",
				Path:  "/spec/externalCIDRs",
				Value: cidrs,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("marshalling failed for CiliumCIDRGroup patch: %w", err)
	}

	if _, err := r.clientset.Patch(ctx, r.fqdnGroup, types.JSONPatchType, cidrsPatch, metav1.PatchOptions{}); err != nil {
		if k8sErrors.IsNotFound(err) {
			cidrGroup := &v2alpha1.CiliumCIDRGroup{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v2alpha1.SchemeGroupVersion.String(),
					Kind:       v2alpha1.CCGKindDefinition,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: r.fqdnGroup,
					Labels: map[string]string{
						"app.kubernetes.io/part-of": "cilium",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: v1alpha1.SchemeGroupVersion.String(),
							Kind:       v1alpha1.IFGKindDefinition,
							Name:       r.fqdnGroup,
							UID:        r.fqdnGroupUID,
						},
					},
				},
				Spec: v2alpha1.CiliumCIDRGroupSpec{
					ExternalCIDRs: cidrs,
				},
			}
			if _, err := r.clientset.Create(ctx, cidrGroup, metav1.CreateOptions{}); err != nil {
				logger.WithError(err).Error("Creation of CiliumCIDRGroup from the IsovalentFQDNGroup failed, will retry")
				return fmt.Errorf("create failed for CiliumCIDRGroup: %w", err)
			}
			return nil
		}
		logger.WithError(err).Error("Patching of CiliumCIDRGroup with updated list of external CIDRs failed, will retry")
		return fmt.Errorf("patch failed for CiliumCIDRGroup: %w", err)
	}

	return nil
}
