// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfEgressCtCmd represents the bpf egress ct command
var bpfEgressCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Manage the egress gateway connection table",
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressCtCmd)
}
