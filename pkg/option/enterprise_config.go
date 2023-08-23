package option

import "github.com/spf13/viper"

// Enterprise specific command line arguments.
const (
	// EnableIPv4EgressGateway enables the IPv4 egress gateway
	EnableIPv4EgressGatewayHA = "enable-ipv4-egress-gateway-ha"
)

type EnterpriseDaemonConfig struct {
	// Enable the HA egress gateway
	EnableIPv4EgressGatewayHA bool
}

func (ec *EnterpriseDaemonConfig) Populate(vp *viper.Viper) {
	ec.EnableIPv4EgressGatewayHA = vp.GetBool(EnableIPv4EgressGatewayHA)
}

func (c *DaemonConfig) EgressGatewayHAEnabled() bool {
	// Enable HA egress gateway if regular egress gateway is enabled to avoid
	// breaking customers already on CEE using --enable-ipv4-egress-gateway to
	// enable HA.
	if c.EnableIPv4EgressGateway {
		return true
	}

	return c.EnableIPv4EgressGatewayHA
}
