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
	"hash"
	"strings"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/identity"
)

const (
	flowTypeL3L4 = "L3/L4"
	flowTypeL7   = "L7"
)

func compareGenericMetadata(f, other types.AggregatableFlow) bool {
	if f.Verdict() != other.Verdict() {
		return false
	}

	if f.DropReasonInt() != other.DropReasonInt() {
		return false
	}

	return true
}

func hashGenericMetadata(h hash.Hash, f types.AggregatableFlow) {
	h.Write([]byte(f.Verdict()))
	h.Write([]byte{
		byte((f.DropReasonInt() >> 0) & 0xFF),
		byte((f.DropReasonInt() >> 8) & 0xFF),
		byte((f.DropReasonInt() >> 16) & 0xFF),
		byte((f.DropReasonInt() >> 24) & 0xFF),
	})
}

func hashSourcePort(h hash.Hash, f types.AggregatableFlow) {
	if f.L4() != nil {
		h.Write([]byte{
			byte(f.L4().SourcePort() & 0xFF),
			byte((f.L4().SourcePort() >> 8) & 0xFF),
		})
	}
}

func hashDestinationPort(h hash.Hash, f types.AggregatableFlow) {
	if f.L4() != nil {
		h.Write([]byte{
			byte(f.L4().DestinationPort() & 0xFF),
			byte((f.L4().DestinationPort() >> 8) & 0xFF),
		})
	}
}

func hashFlowType(h hash.Hash, f types.AggregatableFlow) {
	if f.L7() != nil {
		h.Write([]byte(flowTypeL7))
	} else {
		h.Write([]byte(flowTypeL3L4))
	}
}

// AggregatableFlow is a version of the protobuf Flow which can be used for aggregation
type AggregatableFlow struct {
	*observer.Flow
}

// L3 returns the L3 addressing information
func (f *AggregatableFlow) L3(t types.AddrType) types.L3 {
	if f.IP == nil {
		return nil
	}

	src, dst := f.IP.Source, f.IP.Destination

	if t == types.AddrTypeIdentity && f.Source != nil {
		if identity.NumericIdentity(f.Source.Identity) == identity.ReservedIdentityWorld && len(f.SourceNames) != 0 {
			src = strings.Join(f.SourceNames, ",")
		} else {
			src = strings.Join(f.Source.Labels, ",")
		}
	}

	if t == types.AddrTypeIdentity && f.Destination != nil {
		if identity.NumericIdentity(f.Destination.Identity) == identity.ReservedIdentityWorld && len(f.DestinationNames) != 0 {
			dst = strings.Join(f.DestinationNames, ",")
		} else {
			dst = strings.Join(f.Destination.Labels, ",")
		}
	}

	return types.NewL3Flow([]byte(src), []byte(dst))
}

// L4 returns the L4 addressing information
func (f *AggregatableFlow) L4() types.L4 {
	if tcp := f.GetL4().GetTCP(); tcp != nil {
		return types.NewL4Flow(uint16(tcp.SourcePort&0xffff), uint16(tcp.DestinationPort&0xffff))
	}

	if udp := f.GetL4().GetUDP(); udp != nil {
		return types.NewL4Flow(uint16(udp.SourcePort&0xffff), uint16(udp.DestinationPort&0xffff))
	}

	return nil
}

// L7 returns the L7 information
func (f *AggregatableFlow) L7() types.L7 {
	return &types.L7Flow{
		DNS:   f.GetL7().GetDns(),
		HTTP:  f.GetL7().GetHttp(),
		Kafka: f.GetL7().GetKafka(),
	}
}

// Protocol returns the L4 protocol of the flow
func (f *AggregatableFlow) Protocol() string {
	if f.GetL4() == nil {
		return "None"
	}

	switch {
	case f.GetL4().GetTCP() != nil:
		return "TCP"
	case f.GetL4().GetUDP() != nil:
		return "UDP"
	default:
		return "Other"
	}
}

// Verdict returns the verdict of the flow
func (f *AggregatableFlow) Verdict() string {
	return flow.Verdict_name[int32(f.Flow.Verdict)]
}

// DropReasonInt returns the drop reason of the flow
func (f *AggregatableFlow) DropReasonInt() uint32 {
	return uint32(f.GetDropReasonDesc())
}

// IsReply returns true if the flow represents a reply
func (f *AggregatableFlow) IsReply() bool {
	return f.Flow.GetIsReply().Value
}

// State returns the flow state
func (f *AggregatableFlow) State() (state types.FlowState) {
	if tcp := f.GetL4().GetTCP(); tcp != nil && tcp.Flags != nil {
		state.ConnectionRequest = tcp.Flags.SYN
		state.Error = tcp.Flags.RST
		state.CloseRequest = tcp.Flags.FIN
		state.ACK = tcp.Flags.ACK
	}
	return
}
