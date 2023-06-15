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

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestBasic(t *testing.T) {
	i, err := New()
	assert.NoError(t, err, "constructor should succeed")
	assert.NotNil(t, i, "instance should not be nil")
}

func Test_parseFilterList(t *testing.T) {
	type args struct {
		filters string
	}
	tests := []struct {
		name    string
		args    args
		want    []*pb.FlowFilter
		wantErr bool
	}{
		{
			name: "empty",
			args: args{filters: ""},
			want: nil,
		},
		{
			name: "good",
			args: args{filters: `{"source_label":["reserved:world"]}{"destination_label":["reserved:world"]}`},
			want: []*pb.FlowFilter{
				{SourceLabel: []string{"reserved:world"}},
				{DestinationLabel: []string{"reserved:world"}},
			},
		},
		{
			name:    "bad",
			args:    args{filters: `bad filter string`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFilterList(tt.args.filters)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.want), len(got))

				if tt.want != nil {
					for idx, want := range tt.want {
						g := got[idx]
						assert.True(t, proto.Equal(want, g))
					}
				} else {
					assert.Nil(t, got)
				}
			}
		})
	}
}

func Test_buildFilterFuncs(t *testing.T) {
	filterFuncs, err := buildFilterFuncs(`{"reply":[true]}`)
	assert.NoError(t, err)
	// allowlist
	assert.True(t, filters.Apply(filterFuncs, nil, &v1.Event{Event: &pb.Flow{IsReply: &wrapperspb.BoolValue{Value: true}}}))
	assert.False(t, filters.Apply(filterFuncs, nil, &v1.Event{Event: &pb.Flow{IsReply: &wrapperspb.BoolValue{Value: false}}}))
	// denylist
	assert.True(t, filters.Apply(nil, filterFuncs, &v1.Event{Event: &pb.Flow{IsReply: &wrapperspb.BoolValue{Value: false}}}))
	assert.False(t, filters.Apply(nil, filterFuncs, &v1.Event{Event: &pb.Flow{IsReply: &wrapperspb.BoolValue{Value: true}}}))
}
