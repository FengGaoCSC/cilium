// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/srv6"
)

type importedVRFReconcilerOut struct {
	cell.Out

	Reconciler manager.ConfigReconciler `group:"bgp-config-reconciler"`
}

type importedVRFReconcilerParams struct {
	cell.In

	Logger      logrus.FieldLogger
	SRv6Manager *srv6.Manager
	Clientset   client.Clientset
}

type ImportedVRFReconciler struct {
	logger      logrus.FieldLogger
	srv6Manager *srv6.Manager
	clientset   client.Clientset
}

func NewImportVRFReconciler(params importedVRFReconcilerParams) importedVRFReconcilerOut {
	return importedVRFReconcilerOut{
		Reconciler: &ImportedVRFReconciler{
			logger:      params.Logger,
			srv6Manager: params.SRv6Manager,
			clientset:   params.Clientset,
		},
	}
}

func (r *ImportedVRFReconciler) Priority() int {
	return 50
}

func (r *ImportedVRFReconciler) Reconcile(ctx context.Context, p manager.ReconcileParams) error {
	var (
		l = r.logger.WithFields(
			logrus.Fields{
				"component": "manager.reconcileImportedVRFs",
			},
		)
		toCreate []*srv6.EgressPolicy
		toRemove []*srv6.EgressPolicy
	)

	if !p.DesiredConfig.MapSRv6VRFs {
		l.Infof("VRouter %d will not map learned VPNv4 routes.", p.DesiredConfig.LocalASN)
		return nil
	}

	vrfs := r.srv6Manager.GetAllVRFs()

	curPolicies := r.srv6Manager.GetEgressPolicies()
	l.WithField("count", len(curPolicies)).Debug("Discovered current egress policies")

	newPolicies, err := mapSRv6EgressPolicy(ctx, r.logger, p.CurrentServer, vrfs)
	if err != nil {
		return fmt.Errorf("failed to map VRFs into SRv6 egress policies: %w", err)
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		// present in new policies universe
		a bool
		// present in current policies universe
		b bool
		p *srv6.EgressPolicy
	}

	// set of unique policies
	pset := map[string]*member{}

	// evaluate new policies
	for i, p := range newPolicies {

		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				a: true,
				p: newPolicies[i],
			}
			continue
		}
		h.a = true
	}
	// evaluate current policies
	for i, p := range curPolicies {
		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				b: true,
				p: curPolicies[i],
			}
			continue
		}
		h.b = true
	}

	for _, m := range pset {
		// present in new policies but not in current, create
		if m.a && !m.b {
			toCreate = append(toCreate, m.p)
		}
		// present in current policies but not new, remove.
		if m.b && !m.a {
			toRemove = append(toRemove, m.p)
		}
	}
	l.WithField("count", len(toCreate)).Info("Number of SRv6 egress policies to create.")
	l.WithField("count", len(toRemove)).Info("Number of SRv6 egress policies to remove.")

	clientSet := r.clientset.CiliumV2alpha1().CiliumSRv6EgressPolicies()

	mkName := func(p *srv6.EgressPolicy) (string, error) {
		const prefix = "bgp-control-plane"

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%s-%s", prefix, key), nil
	}

	var name string

	for _, p := range toCreate {
		destCIDRs := []v2alpha1api.CIDR{}
		for _, c := range p.DstCIDRs {
			destCIDRs = append(destCIDRs, v2alpha1api.CIDR(c.String()))
		}

		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		egressPol := &v2alpha1api.CiliumSRv6EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2alpha1",
				Kind:       "CiliumSRv6EgressPolicy",
			},
			Spec: v2alpha1api.CiliumSRv6EgressPolicySpec{
				VRFID:            p.VRFID,
				DestinationCIDRs: []v2alpha1api.CIDR(destCIDRs),
				DestinationSID:   p.SID.IP().String(),
			},
		}
		l.WithField("policy", egressPol).Debug("Writing egress policy to Kubernetes")
		res, err := clientSet.Create(ctx, egressPol, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to write egress policy to Kubernetes: %w", err)
		}
		l.WithField("policy", res).Debug("Resulting egress policy")
	}

	for _, p := range toRemove {
		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		l.WithField("policy", p).Debug("Removing egress policy from Kubernetes")
		err := clientSet.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to remove egress policy: %w", err)
		}
	}

	return nil
}

// keyifySRv6Policy creates a string key for a SRv6PolicyConfig.
func keyifySRv6Policy(p *srv6.EgressPolicy) (string, error) {
	b := &bytes.Buffer{}

	id := strconv.FormatUint(uint64(p.VRFID), 10)
	if _, err := b.Write([]byte(id)); err != nil {
		return "", err
	}

	for _, cidr := range p.DstCIDRs {
		if _, err := b.Write([]byte(cidr.String())); err != nil {
			return "", err
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
