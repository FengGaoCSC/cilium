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
	"bytes"
	"context"
	"hash/adler32"
	"net/url"
	"sort"
	"time"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/cache"

	"github.com/cilium/cilium/api/v1/observer"
)

type connectionAggregation struct {
	types.AggregatableFlow

	addrType         types.AddrType
	ignoreSourcePort bool
}

func (f *connectionAggregation) Compare(other *connectionAggregation) bool {
	if !compareGenericMetadata(f.AggregatableFlow, other.AggregatableFlow) {
		return false
	}

	fL3 := f.L3(f.addrType)
	otherL3 := other.L3(f.addrType)

	if fL3 == nil || otherL3 == nil {
		return false
	}

	if f.Protocol() != other.Protocol() {
		return false
	}

	if (f.L4() != nil) != (other.L4() != nil) {
		return false
	}

	if (f.L7() != nil) != (other.L7() != nil) {
		return false
	}

	if other.IsReply() == f.IsReply() {
		if !bytes.Equal(fL3.Source(), otherL3.Source()) ||
			!bytes.Equal(fL3.Destination(), otherL3.Destination()) {
			return false
		}

		if f.L4() != nil {
			if f.L4().SourcePort() != other.L4().SourcePort() {
				if !f.ignoreSourcePort && !other.IsReply() {
					return false
				}
			}
			if f.L4().DestinationPort() != other.L4().DestinationPort() {
				if !f.ignoreSourcePort && other.IsReply() {
					return false
				}
			}
		}
	} else {
		if !bytes.Equal(fL3.Source(), otherL3.Destination()) ||
			!bytes.Equal(fL3.Destination(), otherL3.Source()) {
			return false
		}

		if f.L4() != nil {
			if f.L4().DestinationPort() != other.L4().SourcePort() {
				if !f.ignoreSourcePort && !other.IsReply() {
					return false
				}
			}
			if f.L4().SourcePort() != other.L4().DestinationPort() {
				if !f.ignoreSourcePort && other.IsReply() {
					return false
				}
			}
		}
	}

	if f.L7() != nil {
		if f.L7().Type() != other.L7().Type() {
			return false
		}

		if dns := f.L7().GetDNS(); dns != nil {
			return looseCompareDNS(dns, other.L7().GetDNS())
		}

		if http := f.L7().GetHTTP(); http != nil {
			return looseCompareHTTP(http, other.L7().GetHTTP())
		}

		if kafka := f.L7().GetKafka(); kafka != nil {
			return compareKafka(kafka, other.L7().GetKafka())
		}
	}

	return true
}

func compareUnorderedStringSlice(a, b []string) bool {
	// Compare the slices lengths before doing any more expensive work
	if len(a) != len(b) {
		return false
	}
	var aa, bb []string
	// Only need to check one slice's length since we know they're both the same length.
	if len(a) == 1 {
		// No need to sort the slices if there's only 1 Qtype (most common).
		aa, bb = a, b
	} else {
		// Copy the slices, since sort modifies the slice
		aa = make([]string, len(a))
		bb = make([]string, len(b))
		copy(aa, a)
		copy(bb, b)
		// Sort the copies of the slices
		sort.Strings(aa)
		sort.Strings(bb)
	}

	for i, v := range aa {
		if v != bb[i] {
			return false
		}
	}
	return true
}

// looseCompareDNS returns true if both DNS flows are loosely identical. This
// means that the following fields must match:
//   - Qtypes
//   - Query
//   - Rcode
//   - Rrtypes
func looseCompareDNS(a, b *observer.DNS) bool {
	return a.Query == b.Query && a.Rcode == b.Rcode && compareUnorderedStringSlice(a.Qtypes, b.Qtypes) && compareUnorderedStringSlice(a.Rrtypes, b.Rrtypes)
}

func stripURLQueryParameters(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	u.RawQuery = ""
	return u.String()
}

// looseCompareHTTP returns true if both HTTP flows are loosely identical. This
// means that the following fields must match:
//   - Code
//   - Method
//   - Url
//   - Protocol
func looseCompareHTTP(a, b *observer.HTTP) bool {
	return a.Code == b.Code && a.Method == b.Method && stripURLQueryParameters(a.Url) == stripURLQueryParameters(b.Url) && a.Protocol == b.Protocol
}

// compareKafka returns true if both Kafka flows are identical
func compareKafka(a, b *observer.Kafka) bool {
	return a.ErrorCode == b.ErrorCode &&
		a.ApiVersion == b.ApiVersion &&
		a.ApiKey == b.ApiKey &&
		a.CorrelationId == b.CorrelationId &&
		a.Topic == b.Topic
}

func (f *connectionAggregation) Hash() types.Hash {
	h := adler32.New()
	hashGenericMetadata(h, f.AggregatableFlow)

	fL3 := f.L3(f.addrType)
	h.Write([]byte(f.Protocol()))

	if f.IsReply() {
		if fL3 != nil {
			h.Write(fL3.Destination())
			h.Write(fL3.Source())
		}

		hashSourcePort(h, f.AggregatableFlow)
		if !f.ignoreSourcePort {
			hashDestinationPort(h, f.AggregatableFlow)
		}
	} else {
		if fL3 != nil {
			h.Write(fL3.Source())
			h.Write(fL3.Destination())
		}

		hashDestinationPort(h, f.AggregatableFlow)
		if !f.ignoreSourcePort {
			hashSourcePort(h, f.AggregatableFlow)
		}
	}

	hashFlowType(h, f.AggregatableFlow)

	return types.Hash(h.Sum32())
}

func newConnectionAggregation(f types.AggregatableFlow, ignoreSourcePort bool) *connectionAggregation {
	return &connectionAggregation{
		AggregatableFlow: f,
		addrType:         types.AddrTypeIdentity,
		ignoreSourcePort: ignoreSourcePort,
	}
}

func aggregateConnection(a *types.AggregatedFlow, _ *observer.DirectionStatistics, f types.AggregatableFlow, r *types.Result) {
	switch {
	case a.Stats.Forward.CloseRequests > 0 && a.Stats.Reply.CloseRequests > 0:
		r.StateChange |= observer.StateChange_closed
	case f.Protocol() == "TCP" && a.Stats.Forward.AckSeen && a.Stats.Reply.AckSeen && !a.Stats.Established:
		r.StateChange |= observer.StateChange_established
		a.Stats.Established = true
	case f.Protocol() != "TCP" && !a.Stats.Established:
		r.StateChange |= observer.StateChange_established
		a.Stats.Established = true
	}
}

// NewConnectionAggregator returns a new connection based aggregator with the
// specified expiration time for flows
func NewConnectionAggregator(ctx context.Context, expiration time.Duration, ignoreSourcePort bool, renewTTL bool) *Aggregator {
	return NewAggregator(ctx, cache.Configuration{
		CompareFunc: func(a, b types.AggregatableFlow) bool {
			ca1, ca2 := newConnectionAggregation(a, ignoreSourcePort), newConnectionAggregation(b, ignoreSourcePort)
			return ca1.Compare(ca2)
		},
		HashFunc: func(f types.AggregatableFlow) types.Hash {
			return newConnectionAggregation(f, ignoreSourcePort).Hash()
		},
		AggregateFunc: aggregateConnection,
		Expiration:    expiration,
		RenewTTL:      renewTTL,
	})
}
