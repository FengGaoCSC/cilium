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
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
)

// Hash is a hash value of a flow. The definition of the hash depends on the
// aggregator. Flows which are going to compare successfully for aggregation,
// must map to the same hash value.
type Hash int64

// FlowCompareFunc is a function to compare two aggregatable flows and must
// return true if the flows match and should thus be aggregated.
type FlowCompareFunc func(a, b AggregatableFlow) bool

// FlowHashFunc is a function to calculate the hash value of a flow. The hash
// value is compared before FlowCompareFunc is invoked on flows.
type FlowHashFunc func(a AggregatableFlow) Hash

// Result is the aggregation result returned by the Aggregate() function
type Result struct {
	// StateChange is the observed change in state as triggered by the flow
	// that was aggregated
	StateChange observer.StateChange

	// Reply indicates whether the latest aggregated flow was seen in the
	// forward or reply direction
	Reply bool

	// AggregatedFlow is the flow with all information aggregated in.
	AggregatedFlow *AggregatedFlow
}

// AggregatedFlow represents the state kept for a set of flows aggregated
// together
type AggregatedFlow struct {
	// Expires is the time in the future in which the state for this
	// aggregated flow expires
	Expires time.Time
	// FirstFlow refers to the first ever flow observed
	FirstFlow AggregatableFlow
	// Stats represents the flow statistics in both the forward and reply
	// direction
	Stats observer.FlowStatistics
}

// Aggregator is the interface that an aggregator has to implement
type Aggregator interface {
	// Aggregate must perform the aggregation logic implemented by the
	// aggregator and return an aggregation result
	Aggregate(f AggregatableFlow) *Result

	// String must return a string representing the configuration of the
	// aggregator
	String() string
}

// AddrType defines an addressing type
type AddrType int

const (
	// AddrTypeIP represents an IP address
	AddrTypeIP AddrType = iota
	// AddrTypeIdentity represents an identity
	AddrTypeIdentity
)

// AggregatableFlow is the interface a flow must implement in order to be
// compatible for aggregation
type AggregatableFlow interface {
	// L3 must return L3 information
	L3(t AddrType) L3

	// L3 must return L4 information
	L4() L4

	// L7 can return L7 information (may be nil)
	L7() L7

	// Protocol must return the L4 protocol
	Protocol() string

	// Verdict must return the forward verdict
	Verdict() string

	// DropReasonInt must return the drop reason in numeric form
	DropReasonInt() uint32

	// IsReply must return true if the flow  has been observed in reply
	// direction
	IsReply() bool

	// State must return the flow state
	State() FlowState
}

// FlowState is a representation of certain flow transition requests in
// abstract form. This allows to map TCP flags or HTTP status code to a generic
// structure and avoiding aggregators to understand a wide set of different
// transport or application protocols.
type FlowState struct {
	// ConnectionRequest is true when the flow requests creating of a connection
	ConnectionRequest bool
	// Error is true when the flow indicates an error
	Error bool
	// CloseRequest is true when the flow requests closing of a connection
	CloseRequest bool
	// ACK is true when data is being acknowledged
	ACK bool
}

// L3 represents L3 addressing information
type L3 interface {
	// Source is the source address. This can be an IP address, pod name,
	// FQDN name, ...
	Source() []byte
	// Destination is the destination address. This can be an IP address,
	// pod name, FQDN name, ...
	Destination() []byte
}

// L4 represents L4 addressing information
type L4 interface {
	// SourcePort is the source port of the flow
	SourcePort() uint16
	// DestinationPort is the destination port of the flow
	DestinationPort() uint16
}

// L7 contains L7 information and may be nil
type L7 interface {
	// Type returns the type of L7 flow
	Type() L7Type

	// GetHTTP must return the HTTP flow information
	GetHTTP() *flow.HTTP

	// GetDNS must return the DNS flow information
	GetDNS() *flow.DNS

	// GetKafka must return the Kafka flow information
	GetKafka() *flow.Kafka
}

type l3Flow struct {
	source      []byte
	destination []byte
}

// NewL3Flow returns an implementation of the L3 interface for a given source
// and destination string
func NewL3Flow(source, destination []byte) L3 {
	return &l3Flow{
		source:      source,
		destination: destination,
	}
}

func (l *l3Flow) Source() []byte {
	return l.source
}

func (l *l3Flow) Destination() []byte {
	return l.destination
}

type l4Flow struct {
	source      uint16
	destination uint16
}

// NewL4Flow returns an implementation of the L4 interface for a given source
// and destination port
func NewL4Flow(source, destination uint16) L4 {
	return &l4Flow{
		source:      source,
		destination: destination,
	}
}

func (l *l4Flow) SourcePort() uint16 {
	return l.source
}

func (l *l4Flow) DestinationPort() uint16 {
	return l.destination
}

// L7Flow defines the collection of all L7 protocols by the aggregation logic
type L7Flow struct {
	HTTP  *flow.HTTP
	DNS   *flow.DNS
	Kafka *flow.Kafka
}

// Type returns the Layer 7 type of the flow
func (l *L7Flow) Type() L7Type {
	if l == nil {
		return L7NameNone
	}

	switch {
	case l.GetDNS() != nil:
		return L7NameDNS
	case l.GetHTTP() != nil:
		return L7NameHTTP
	case l.GetKafka() != nil:
		return L7NameKafka
	}

	return L7NameUnknown
}

// GetHTTP returns the HTTP flow information if available
func (l *L7Flow) GetHTTP() *flow.HTTP {
	if l == nil {
		return nil
	}

	return l.HTTP
}

// GetDNS returns the DNS flow information if available
func (l *L7Flow) GetDNS() *flow.DNS {
	if l == nil {
		return nil
	}

	return l.DNS
}

// GetKafka returns the Kafka flow information if available
func (l *L7Flow) GetKafka() *flow.Kafka {
	if l == nil {
		return nil
	}

	return l.Kafka
}
