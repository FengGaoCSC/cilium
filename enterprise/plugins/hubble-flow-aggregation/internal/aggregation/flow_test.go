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
)

func TestGenericMetadataCompare(_ *testing.T) {
	// TODO: uncomment the tests, obviously. At the moment the problem is that
	// `AggregatableFlow` (AF) is defined in the covalentio/hubble-enterprise
	// repo (which is the repo being broken up). AF embeds proto.Flow which in
	// the Atlantis build is going to be the Flow after all the plugins get a
	// chance to Mutate the proto. Basically, these tests probably need to be
	// rewritten using interfaces rather than concrete proto structs.

	// assert.True(t, compareGenericMetadata(
	// 	&testflow.Flow{Verdict: pb.Verdict_FORWARDED, DropReason: 0},
	// 	&testflow.Flow{Verdict: pb.Verdict_FORWARDED, DropReason: 0},
	// ))

	// assert.True(t, compareGenericMetadata(
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_DROPPED, DropReason: 0}},
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_DROPPED, DropReason: 0}},
	// ))

	// assert.False(t, compareGenericMetadata(
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_FORWARDED, DropReason: 0}},
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_DROPPED, DropReason: 0}},
	// ))

	// assert.False(t, compareGenericMetadata(
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_DROPPED, DropReason: 10}},
	// 	&v1.AggregatableFlow{Flow: &observer.Flow{Verdict: pb.Verdict_DROPPED, DropReason: 20}},
	// ))
}
