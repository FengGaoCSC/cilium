// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policymetadata

import (
	"context"
	"fmt"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/plugins"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"

	"github.com/sirupsen/logrus"
)

var (
	// validate interface conformity
	_ plugins.ServerOptions = (*flowPolicyMetadata)(nil)
)

type policyCorrelation struct {
	endpointGetter getters.EndpointGetter
	logger         logrus.FieldLogger
}

type flowPolicyMetadata struct {
	policyCorrelation *policyCorrelation // initialized in OnServerInit
}

// New ...
func New() (plugins.Instance, error) {
	return &flowPolicyMetadata{}, nil
}

func (m *flowPolicyMetadata) Name() string {
	return "policy-metadata"
}

func (m *flowPolicyMetadata) OnServerInit(srv observeroption.Server) error {
	endpointGetter, ok := srv.GetOptions().CiliumDaemon.(getters.EndpointGetter)
	if !ok || endpointGetter == nil {
		return fmt.Errorf("%s: failed to obtain reference to cilium daemon", m.Name())
	}

	m.policyCorrelation = &policyCorrelation{
		endpointGetter: endpointGetter,
		logger:         srv.GetLogger(),
	}

	return nil
}

func (m *flowPolicyMetadata) OnDecodedFlow(ctx context.Context, f *pb.Flow) (bool, error) {
	if m.policyCorrelation == nil {
		return false, nil
	}

	if err := m.policyCorrelation.correlatePolicy(f); err != nil {
		// correlatePolicy only returns an error in fatal cases, disable it
		m.policyCorrelation = nil
		return false, fmt.Errorf("%s: %s", m.Name(), err)
	}
	return false, nil
}

func (m *flowPolicyMetadata) ServerOptions() []observeroption.Option {
	return []observeroption.Option{
		observeroption.WithOnServerInit(m),
		observeroption.WithOnDecodedFlow(m),
	}
}
