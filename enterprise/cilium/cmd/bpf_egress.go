// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium/cmd"
)

// BPFEgressCmd represents the bpf command
var BPFEgressCmd = &cobra.Command{
	Use:   "egress",
	Short: "Manage the egress routing rules",
}

func init() {
	cmd.BPFCmd.AddCommand(BPFEgressCmd)
}
