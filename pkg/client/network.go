// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/network"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// NetworkAttachments returns the network attachments for a given pod
func (c *Client) NetworkAttachments(podNamespace, podName string) (*models.NetworkAttachmentList, error) {
	params := network.NewGetNetworkAttachmentParams().
		WithPodNamespace(podNamespace).
		WithPodName(podName).
		WithTimeout(api.ClientTimeout)

	resp, err := c.Network.GetNetworkAttachment(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
