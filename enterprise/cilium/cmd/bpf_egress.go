// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium/cmd"
)

var bpfEgressCmd = &cobra.Command{
	Use:   "egress-ha",
	Short: "Manage the egress gateway HA rules",
}

func init() {
	cmd.BPFCmd.AddCommand(bpfEgressCmd)
}
