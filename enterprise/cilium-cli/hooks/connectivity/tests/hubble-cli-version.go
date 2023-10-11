//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"strings"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
)

func HubbleCLIVersion() check.Scenario {
	return &hubbleCLIVersion{}
}

type hubbleCLIVersion struct{}

func (s *hubbleCLIVersion) Name() string {
	return "hubble-cli-version"
}

func (s *hubbleCLIVersion) Run(ctx context.Context, t *check.Test) {
	for name, pod := range t.Context().CiliumPods() {
		t.NewAction(s, name, &pod, nil, features.IPFamilyAny).Run(func(a *check.Action) {
			cmd := []string{"hubble", "version"}
			stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				t.Fatalf("'%s' failed on %s: %s", cmd, pod.Name(), err)
			}
			version := strings.TrimSpace(stdout.String())
			if !strings.Contains(version, "cee") {
				t.Fatalf("hubble version on %s does not contain 'cee': %s", pod.Name(), version)
			}
			t.Debugf("Found a valid hubble cee version: %s", version)
		})
	}
}
