package loader

// Enterprise specific prefixes.
func init() {
	ignoredELFPrefixes = append(ignoredELFPrefixes,
		"cilium_egress_gw_ha_policy_v4", // Global
		"cilium_egress_gw_ha_ct_v4",     // Global
	)
}
