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

// L7Type is a Layer 7 type as supported by the aggregation engine
type L7Type string

const (
	// L7NameNone is used when the flow is not an L7 flow
	L7NameNone L7Type = "none"

	// L7NameHTTP is used to represent HTTP and HTTP/2 flows
	L7NameHTTP L7Type = "http"

	// L7NameKafka is used to represents Kafka protocol flows
	L7NameKafka L7Type = "kafka"

	// L7NameDNS is used to represent flows referring to to DNS requests
	// and responses
	L7NameDNS L7Type = "dns"

	// L7NameUnknown is used when the L7 protocol is unknown and thus not
	// supported
	L7NameUnknown L7Type = "unknown"
)
