// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/network"
)

type getNetworkAttachment struct {
	daemon *Daemon
}

// NewGetNetworkAttachmentHandler returns a new /network/attachment handler
func NewGetNetworkAttachmentHandler(d *Daemon) restapi.GetNetworkAttachmentHandler {
	return &getNetworkAttachment{daemon: d}
}

func (g getNetworkAttachment) Handle(params restapi.GetNetworkAttachmentParams) middleware.Responder {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()

	if g.daemon.multiNetworkManager == nil {
		return restapi.NewGetNetworkAttachmentDisabled()
	}

	payload, err := g.daemon.multiNetworkManager.GetNetworksForPod(ctx, params.PodNamespace, params.PodName)
	if err != nil {
		return restapi.NewGetNetworkAttachmentFailure().WithPayload(models.Error(err.Error()))
	}

	return restapi.NewGetNetworkAttachmentOK().
		WithPayload(payload)
}
