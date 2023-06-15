// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func Test_getLimit(t *testing.T) {
	assert.Equal(t, rate.Limit(0), getLimit(0, time.Minute))
	assert.Equal(t, rate.Limit(0), getLimit(0, 0))
	assert.Equal(t, rate.Limit(1), getLimit(60, time.Minute))
	assert.Equal(t, rate.Limit(10.0/60), getLimit(10, time.Minute))
	// 1/ms => 1000/second
	assert.Equal(t, rate.Limit(1000), getLimit(1, time.Millisecond))
	// 3600/hour => 1/second
	assert.Equal(t, rate.Limit(1), getLimit(60*60, time.Hour))

	// interval<=0 => infinite rate limit (allow all events)
	assert.Equal(t, rate.Inf, getLimit(1, 0))
	assert.Equal(t, rate.Inf, getLimit(1, -1))
}
