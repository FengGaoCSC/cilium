// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"testing"

	"github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
)

func TestConfigureAggregator(t *testing.T) {
	assert.EqualValues(t, (&L7Flow{HTTP: &flow.HTTP{}}).Type(), L7NameHTTP)
	assert.EqualValues(t, (&L7Flow{Kafka: &flow.Kafka{}}).Type(), L7NameKafka)
	assert.EqualValues(t, (&L7Flow{DNS: &flow.DNS{}}).Type(), L7NameDNS)
	assert.EqualValues(t, (&L7Flow{}).Type(), L7NameUnknown)
	var nilL7 *L7Flow
	assert.EqualValues(t, nilL7.Type(), L7NameNone)
}
