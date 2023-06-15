// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregation

import (
	"testing"

	"github.com/cilium/cilium/api/v1/observer"

	"github.com/stretchr/testify/assert"
)

func TestConfigureAggregator(t *testing.T) {
	a, err := ConfigureAggregator([]*observer.Aggregator{})
	assert.True(t, err == nil)
	assert.True(t, a == nil)

	a, err = ConfigureAggregator([]*observer.Aggregator{{Type: 10000}})
	assert.True(t, err != nil)
	assert.True(t, a == nil)

	a, err = ConfigureAggregator([]*observer.Aggregator{{Type: observer.AggregatorType_identity}})
	assert.True(t, err == nil)
	assert.True(t, a.String() == "compare")

	a, err = ConfigureAggregator([]*observer.Aggregator{{Type: observer.AggregatorType_identity}, {Type: observer.AggregatorType_connection}})
	assert.True(t, err == nil)
	assert.True(t, a.String()[0] == '[')
}
