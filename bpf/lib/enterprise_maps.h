/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_EGRESS_GATEWAY_HA
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_ha_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_HA_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} EGRESS_GW_HA_POLICY_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct egress_gw_ha_ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_HA_CT_MAP_SIZE);
} EGRESS_GW_HA_CT_MAP __section_maps_btf;
#endif /* ENABLE_EGRESS_GATEWAY_HA */

