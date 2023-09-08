// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"

	"github.com/spf13/cobra"
)

const (
	egressCtListUsage = "List egress CT entries.\n"
)

type EgressCt struct {
	SourceIP  string
	DestIP    string
	Proto     uint8
	SrcPort   uint16
	DstPort   uint16
	GatewayIP string
}

var bpfEgressCtListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress CT entries",
	Long:    egressCtListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress ct list")

		ctMap, err := egressmapha.OpenPinnedCtMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				Fatalf("Cannot find egress gateway bpf maps")
			}

			Fatalf("Cannot open egress gateway bpf maps: %s", err)
		}

		bpfEgressCtList := []EgressCt{}
		parse := func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			bpfEgressCtList = append(bpfEgressCtList, EgressCt{
				SourceIP:  key.SourceAddr.String(),
				DestIP:    key.DestAddr.String(),
				Proto:     uint8(key.NextHeader),
				SrcPort:   byteorder.NetworkToHost16(key.SourcePort),
				DstPort:   byteorder.NetworkToHost16(key.DestPort),
				GatewayIP: val.Gateway.String(),
			})
		}

		if err := ctMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping content of egress CT map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfEgressCtList); err != nil {
				Fatalf("Error getting output of map in JSON: %s\n", err)
			}
			return
		}

		printEgressCtList(bpfEgressCtList)
	},
}

func printEgressCtList(ctList []EgressCt) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Src IP\tDst IP\tProto\tSrc Port\tDst Port\tGateway IP")

	for _, ct := range ctList {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
			ct.SourceIP, ct.DestIP, ct.Proto,
			ct.SrcPort, ct.DstPort, ct.GatewayIP)
	}

	w.Flush()
}

func init() {
	bpfEgressCtCmd.AddCommand(bpfEgressCtListCmd)
	command.AddOutputOption(bpfEgressCtListCmd)
}
