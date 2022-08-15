// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/types"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ips are endpoint's unique IPs
	ips []net.IP
}

// endpointID includes endpoint name and namespace
type endpointID = types.NamespacedName

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint,
	identityLabels labels.Labels) (*endpointMetadata, error) {
	var ips []net.IP
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ips = append(ips, net.ParseIP(pair.IPV4).To4())
		}
		if pair.IPV6 != "" {
			ips = append(ips, net.ParseIP(pair.IPV6).To16())
		}
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ips:    ips,
		labels: identityLabels.K8sStringMap(),
		id:     id,
	}

	return data, nil
}
