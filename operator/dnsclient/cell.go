// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsclient

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// ServerAddresses is a list of DNS servers addresses in the form "<ip>:<port>"
	// to be used from the operator dns client.
	// If multiple servers are set, the client queries them in the order listed.
	DNSServerAddresses = "dns-server-addresses"
)

var Cell = cell.Module(
	"dns-client",
	"Isovalent DNS client",

	cell.Config(Config{}),
	cell.Provide(newClient),
)

type Config struct {
	DNSServerAddresses []string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(
		DNSServerAddresses,
		nil,
		"A list of DNS server addresses to be used by the operator DNS client for resolution of FQDNs in IsovalentFQDNGroup CRDs. Each address should be in the form \"<ip>:<port>\". "+
			"When resolving an FQDN, the operator will try to query the first server. If it fails, it will try the next one and so on, following the order specified by the user.",
	)
}
