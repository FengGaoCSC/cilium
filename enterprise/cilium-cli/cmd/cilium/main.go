//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"os"

	cfsslLog "github.com/cloudflare/cfssl/log"

	"github.com/cilium/cilium-cli/cli"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks"
)

func main() {
	// Hide unwanted cfssl log messages
	cfsslLog.Level = cfsslLog.LevelWarning

	if err := cli.NewCiliumCommand(&hooks.EnterpriseHooks{}).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
