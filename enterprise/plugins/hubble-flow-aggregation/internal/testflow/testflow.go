// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testflow

import (
	"hash/adler32"
	"net"

	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
)

// Peer is a peer for test flows
type Peer struct {
	Identity []byte
	IP       net.IP
	Port     uint16
}

// Compare returns true if two peers match
func (p Peer) Compare(b Peer) bool {
	return p.Port == b.Port && p.IP.Equal(b.IP)
}

// L7 contains L7 information
type L7 struct {
	HasDNS bool
}

// FlowEmbed is a dummy struct that embeds a flow for testing
type FlowEmbed struct {
	*Flow
}

// Flow is a dummy flow for testing
type Flow struct {
	Source      Peer
	Destination Peer
	ProtocolStr string
	VerdictStr  string
	DropReason  uint32
	Reply       bool
	FlowState   types.FlowState
	L7Data      *types.L7Flow
}

// Compare returns true if two flows match
func (f *Flow) Compare(b *Flow) bool {
	return f.Source.Compare(b.Source) &&
		f.Destination.Compare(b.Destination) &&
		f.VerdictStr == b.VerdictStr &&
		f.DropReason == b.DropReason &&
		f.Reply == b.Reply &&
		f.ProtocolStr == b.ProtocolStr
}

// L3 returns L3 addressing information of a flow
func (f *Flow) L3(t types.AddrType) types.L3 {
	var src, dst = f.Source.IP, f.Destination.IP
	if t == types.AddrTypeIdentity && len(f.Source.Identity) > 0 {
		src = f.Source.Identity
	}
	if t == types.AddrTypeIdentity && len(f.Destination.Identity) > 0 {
		dst = f.Destination.Identity
	}
	return types.NewL3Flow(src, dst)
}

// L4 returns L4 addressing information of a flow
func (f *Flow) L4() types.L4 {
	return types.NewL4Flow(f.Source.Port, f.Destination.Port)
}

// L7 returns L7 information of a flow
func (f *Flow) L7() types.L7 {
	return f.L7Data
}

// Protocol returns the protocol of the flow
func (f *Flow) Protocol() string {
	return f.ProtocolStr
}

// Verdict returns the verdict of a flow
func (f *Flow) Verdict() string {
	return f.VerdictStr
}

// DropReasonInt returns the drop reason of a flow
func (f *Flow) DropReasonInt() uint32 {
	return f.DropReason
}

// IsReply returns true if the flow represents a reply
func (f *Flow) IsReply() bool {
	return f.Reply
}

// State returns the flow state
func (f *Flow) State() types.FlowState {
	return f.FlowState
}

// Compare implements the aggregation.FlowCompareFunc
func Compare(aObj, bObj types.AggregatableFlow) bool {
	a, aOK := aObj.(*Flow)
	b, bOK := bObj.(*Flow)
	if !aOK || !bOK {
		return false
	}

	return a.Compare(b)
}

// Hash implements the aggregation.FlowHashFunc
func Hash(fObj types.AggregatableFlow) types.Hash {
	f, ok := fObj.(*Flow)
	if !ok {
		return 0
	}

	h := adler32.New()

	h.Write([]byte(f.Verdict()))
	h.Write([]byte(f.Protocol()))

	h.Write([]byte{
		byte((f.DropReasonInt() >> 0) & 0xFF),
		byte((f.DropReasonInt() >> 8) & 0xFF),
		byte((f.DropReasonInt() >> 16) & 0xFF),
		byte((f.DropReasonInt() >> 24) & 0xFF),
	})

	h.Write([]byte{byte(f.L4().SourcePort() & 0xFF), byte((f.L4().SourcePort() >> 8) & 0xFF)})
	h.Write([]byte{byte(f.L4().DestinationPort() & 0xFF), byte((f.L4().DestinationPort() >> 8) & 0xFF)})

	h.Write(f.L3(types.AddrTypeIP).Source())
	h.Write(f.L3(types.AddrTypeIP).Destination())

	return types.Hash(h.Sum32())
}
