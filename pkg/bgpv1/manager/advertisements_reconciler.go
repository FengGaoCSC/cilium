// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type AdvertisementsReconcilerParams struct {
	Ctx       context.Context
	Name      string
	Component string
	Enabled   bool

	SC   *ServerWithConfig
	NewC *v2alpha1api.CiliumBGPVirtualRouter

	CurrentAdvertisements []*types.Path
	ToAdvertise           []*types.Path
}

// ExportAdvertisementsReconciler reconciles the state of the BGP advertisements
// with the provided toAdvertise list and returns a list of the advertisements
// currently being announced.
func ExportAdvertisementsReconciler(params *AdvertisementsReconcilerParams) ([]*types.Path, error) {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": params.Component,
			},
		)
		// holds advertisements which must be advertised
		toAdvertise []*types.Path
		// holds advertisements which must remain in place
		toKeep []*types.Path
		// holds advertisements which must be removed
		toWithdraw []*types.Path
		// the result of advertising toAdvertise.
		newAdverts []*types.Path
	)

	l.Debugf("Begin reconciling %s advertisements for virtual router with local ASN %v", params.Name, params.NewC.LocalASN)

	// if advertisement is turned off withdraw any previously advertised
	// cidrs and early return nil.
	if !params.Enabled {
		l.Debugf("%s advertisements disabled for virtual router with local ASN %v", params.Name, params.NewC.LocalASN)

		for _, advrt := range params.CurrentAdvertisements {
			l.Debugf("Withdrawing %s advertisement %v for local ASN %v", params.Name, advrt.NLRI, params.NewC.LocalASN)
			if err := params.SC.Server.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
				return nil, err
			}
		}

		return nil, nil
	}

	// an aset member which book keeps which universe it exists in
	type member struct {
		a     bool
		b     bool
		advrt *types.Path
	}

	aset := map[string]*member{}

	// populate the advrts that must be present, universe a
	for _, path := range params.ToAdvertise {
		var (
			m  *member
			ok bool
		)

		key := path.NLRI.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				a:     true,
				advrt: path,
			}
			continue
		}
		m.a = true
	}

	// populate the advrts that are current advertised
	for _, path := range params.CurrentAdvertisements {
		var (
			m  *member
			ok bool
		)
		key := path.NLRI.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				b:     true,
				advrt: path,
			}
			continue
		}
		m.b = true
	}

	for _, m := range aset {
		// present in configured cidrs (set a) but not in advertised cidrs
		// (set b)
		if m.a && !m.b {
			toAdvertise = append(toAdvertise, m.advrt)
		}
		// present in advertised cidrs (set b) but no in configured cidrs
		// (set b)
		if m.b && !m.a {
			toWithdraw = append(toWithdraw, m.advrt)
		}
		// present in both configured (set a) and advertised (set b) add this to
		// cidrs to leave advertised.
		if m.b && m.a {
			toKeep = append(toKeep, m.advrt)
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		l.Debugf("No reconciliation necessary")
		return append([]*types.Path{}, params.CurrentAdvertisements...), nil
	}

	// create new adverts
	for _, advrt := range toAdvertise {
		l.Debugf("Advertising %s %v for policy with local ASN: %v", params.Name, advrt.NLRI, params.NewC.LocalASN)
		advrtResp, err := params.SC.Server.AdvertisePath(params.Ctx, types.PathRequest{Path: advrt})
		if err != nil {
			return nil, fmt.Errorf("failed to advertise %s prefix %v: %w", params.Name, advrt.NLRI, err)
		}
		newAdverts = append(newAdverts, advrtResp.Path)
	}

	// withdraw uneeded adverts
	for _, advrt := range toWithdraw {
		l.Debugf("Withdrawing %s %v for policy with local ASN: %v", params.Name, advrt.NLRI, params.NewC.LocalASN)
		if err := params.SC.Server.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
			return nil, err
		}
	}

	// concat our toKeep and newAdverts slices to store the latest
	// reconciliation and return it
	return append(toKeep, newAdverts...), nil
}
