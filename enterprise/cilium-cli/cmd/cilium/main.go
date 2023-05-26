// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium-cli/cli"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks"
)

func main() {
	if err := cli.NewCiliumCommand(&hooks.EnterpriseHooks{}).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
